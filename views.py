import json
import os
import secrets
import sys
import traceback
from typing import Union
from urllib.parse import urlparse
from uuid import uuid4

import requests

from cryptojwt import as_unicode
from cryptojwt.exception import VerificationError
from flask import Blueprint
from flask import Response
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify, abort
from flask.helpers import make_response
from flask.helpers import send_from_directory
import urllib.parse

from idpyoidc.client.oauth2.introspection import Introspection
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
import werkzeug

from idpyoidc.server.exception import FailedAuthentication
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import UnAuthorizedClient
from idpyoidc.server.oidc.token import Token

# logger = logging.getLogger(__name__)

oidc_op_views = Blueprint("oidc_op", __name__, url_prefix="")
from application import request_manager
from security import backend_api_key_error, redact, session_token
import dpop


def _add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    kwargs = {k: v for k, v in cookie_spec.items() if k not in ("name",)}
    kwargs["path"] = "/"
    kwargs["samesite"] = "Lax"
    kwargs["secure"] = True
    kwargs["httponly"] = True
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)


@oidc_op_views.route("/static/<path:path>")
def send_js(path):
    return send_from_directory("static", path)


@oidc_op_views.route("/keys/<jwks>")
def keys(jwks):
    fname = os.path.join("static", jwks)
    return open(fname).read()


@oidc_op_views.route("/")
def index():
    return render_template("index.html")


# def add_headers_and_cookie(resp, info):
#     return resp


def do_response(endpoint, req_args, error="", **args) -> Response:
    info = endpoint.do_response(request=req_args, error=error, **args)
    _log = current_app.logger
    _log.debug("do_response: {}".format(redact(info)))

    try:
        _response_placement = info["response_placement"]
    except KeyError:
        _response_placement = endpoint.response_placement

    _log.debug("response_placement: {}".format(_response_placement))

    if error:
        if _response_placement == "body":
            _log.info("Error Response: {}".format(redact(info["response"])))
            _http_response_code = info.get("response_code", 400)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info("Error redirect issued")
            resp = redirect(info["response"])
    else:
        if _response_placement == "body":
            _log.debug("Response: {}".format(redact(info["response"])))
            _http_response_code = info.get("response_code", 200)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info("Redirect issued")
            resp = redirect(info["response"])

    for key, value in info["http_headers"]:
        resp.headers[key] = value

    if "cookie" in info:
        add_cookie(resp, info["cookie"])

    return resp


# Error redirection to the wallet during authentication
def authentication_error_redirect(jws_token, error, error_description):
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        auth_args = authn_method.unpack_token(jws_token)
    except:
        return make_response(
            json.dumps(
                {"error": "invalid_request", "error_description": "Cookie Lost"}
            ),
            400,
        )

    if error is None:
        error = "invalid_request"

    if error_description is None:
        error_description = "invalid_request"

    return redirect(
        auth_args["return_uri"]
        + "?"
        + urllib.parse.urlencode(
            {
                "error": error,
                "error_description": error_description,
            }
        ),
        code=302,
    )


# Error redirection to the wallet during authentication without jws_token
def auth_error_redirect(return_uri, error, error_description=None):

    error_msg = {
        "error": error,
    }

    if error_description is not None:
        error_msg["error_description"] = error_description

    return redirect(
        return_uri + "?" + urllib.parse.urlencode(error_msg),
        code=302,
    )


def _session_matches_request(session_id, authz_request) -> bool:
    """Tells whether an issuance session belongs to an authorization request.

    Args:
        session_id: Session id sent back by the issuer backend.
        authz_request: Authorization request from the signed token.

    Returns:
        True when the session was created for this client, redirect URI,
        state and PKCE challenge.
    """
    current_request = request_manager.get_request(session_id=session_id)
    if current_request is None:
        return False
    for name in ("client_id", "redirect_uri", "state", "code_challenge"):
        stored = getattr(current_request, name, None)
        if (stored or None) != (authz_request.get(name) or None):
            return False
    return True


def verify(authn_method):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """
    # kwargs = dict([(k, v) for k, v in request.form.items()])

    try:
        username = authn_method.verify(username=request.args.get("username"))

        auth_args = authn_method.unpack_token(request.args.get("token"))
    except:
        current_app.logger.error(
            "Authorization verification: username or jws_token not found"
        )
        if "jws_token" in request.args:
            return authentication_error_redirect(
                jws_token=request.args.get("jws_token"),
                error="invalid_request",
                error_description="Authentication verification Error",
            )
        else:
            return "Internal Server Error", 500
            # return render_template("misc/500.html", error="Authentication verification Error")

    authz_request = AuthorizationRequest().from_urlencoded(auth_args["query"])

    # The token proves which authorization request is being completed; the
    # username (issuance session) must be the one created for that request,
    # or anyone holding a token could complete it with another session.
    if not _session_matches_request(username, authz_request):
        current_app.logger.warning(
            f"Authorization verification: session {username} does not match the token's request"
        )
        return make_response(
            json.dumps(
                {"error": "invalid_request", "error_description": "Session mismatch"}
            ),
            400,
        )

    endpoint = current_app.server.get_endpoint("authorization")

    _session_id = endpoint.create_session(
        authz_request,
        username,
        auth_args["authn_class_ref"],
        auth_args["iat"],
        authn_method,
    )

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    # authz_part2 returns a dict and reports errors inside response_args
    response_dict = args.get("response_args").to_dict()

    if "error" in response_dict:
        current_app.logger.error(
            f"authz_part2 returned error for session {username}: {response_dict}"
        )
        return make_response(json.dumps(response_dict), 400)

    code = response_dict.get("code")
    if code is None:
        current_app.logger.error(
            f"No 'code' in response_args for session {username}: {response_dict}"
        )
        return make_response(
            json.dumps(
                {"error": "server_error", "error_description": "no code issued"}
            ),
            500,
        )

    request_manager.update_code(session_id=username, code=code)

    return do_response(endpoint, request, **args)


@oidc_op_views.route("/verify/user", methods=["GET", "POST"])
def verify_user():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        return render_template("error.html", title=str(exc))


@oidc_op_views.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-configuration" or service == "oauth-authorization-server":
        return send_from_directory(current_app.root_path, "openid-configuration.json")
    elif service == "webfinger":
        _endpoint = current_app.server.get_endpoint("discovery")
    else:
        return make_response("Not supported", 400)

    return service_endpoint(_endpoint)


@oidc_op_views.route("/registration", methods=["GET", "POST"])
def registration():
    return service_endpoint(current_app.server.get_endpoint("registration"))


@oidc_op_views.route("/registration_api", methods=["GET", "DELETE"])
def registration_api():
    if request.method == "DELETE":
        return service_endpoint(current_app.server.get_endpoint("registration_delete"))
    else:
        return service_endpoint(current_app.server.get_endpoint("registration_read"))


def dynamic_registration(client_id, redirect_uri):
    _context = current_app.server.get_context()
    # process_request_authorization replaces the client's redirect_uris with only
    # the new one, so keep the previous ones to not break in-flight sessions
    previous_uris = list(_context.cdb.get(client_id, {}).get("redirect_uris", []))
    try:
        current_app.server.get_endpoint("registration").process_request_authorization(
            client_id=client_id, redirect_uri=redirect_uri
        )

        _cinfo = _context.cdb[client_id]
        merged_uris = list(_cinfo.get("redirect_uris", []))
        for uri in previous_uris:
            if uri not in merged_uris:
                merged_uris.append(uri)
        _cinfo["redirect_uris"] = merged_uris
        _context.cdb[client_id] = _cinfo
    except Exception as e:
        current_app.logger.error(
            f"Error during client registration/update in traditional flow: {e}"
        )
        return auth_error_redirect(
            redirect_uri, "server_error", "client_registration_failed"
        )


@oidc_op_views.route("/authorization")
def authorization():
    # 1. Handle PAR Authorization Request

    request_manager.clean_expired_requests()
    if "request_uri" in request.args:
        request_uri = request.args.get("request_uri")

        if not request_uri:
            current_app.logger.warning(
                "Authorization Request: 'request_uri' is missing from the request."
            )
            abort(400, "Bad Request: 'request_uri' parameter is mandatory.")

        current_request = request_manager.get_request_by_uri(request_uri)

        if not current_request:
            current_app.logger.warning(
                f"Authorization Request: No matching request found for URI: {request_uri}"
            )
            abort(
                404, "Not Found: No authorization request found for the provided URI."
            )

        session_id = current_request.session_id

        current_app.logger.info(
            f"Session ID: {session_id}, Authorization Request (PAR), Payload: {redact(request.args.to_dict())}"
        )

        scope = current_request.scope
        authorization_details = None

        authorization_args = {
            "client_id": current_request.client_id,
            "redirect_uri": current_request.redirect_uri,
            "scope": current_request.scope,
            "client_id": current_request.client_id,
            "request_uri": current_request.request_uri,
            "response_type": current_request.response_type,
        }

        if hasattr(current_request, "state") and current_request.state:
            authorization_args["state"] = current_request.state
        if (
            hasattr(current_request, "code_challenge_method")
            and current_request.code_challenge_method
        ):
            authorization_args["code_challenge_method"] = (
                current_request.code_challenge_method
            )
        if (
            hasattr(current_request, "code_challenge")
            and current_request.code_challenge
        ):
            authorization_args["code_challenge"] = current_request.code_challenge
        if (
            hasattr(current_request, "authorization_details")
            and current_request.authorization_details
        ):
            authorization_details = current_request.authorization_details
            authorization_args["authorization_details"] = (
                current_request.authorization_details
            )

    else:
        session_id = str(uuid4())

        current_app.logger.info(
            f"Session ID: {session_id}, Authorization Request (Non-PAR), Payload: {redact(request.args.to_dict())}"
        )

        try:
            client_id = request.args.get("client_id")
            redirect_uri = request.args.get("redirect_uri")
            response_type = request.args.get("response_type")
            scope = request.args.get("scope")
            code_challenge_method = request.args.get("code_challenge_method")
            code_challenge = request.args.get("code_challenge")
            authorization_details = request.args.get("authorization_details")
            state = request.args.get("state")
            issuer_state = request.args.get("issuer_state")

            if not all([client_id, redirect_uri, response_type]):
                current_app.logger.error(
                    "Missing required parameters for traditional authorization."
                )
                return make_response("Missing required parameters", 400)

        except (
            Exception
        ) as e:  # Catch broad exception for simplicity, refine in production
            current_app.logger.error(f"Authorization request error: {e}")
            return make_response("Authorization request invalid parameters", 400)

        dynamic_registration(client_id=client_id, redirect_uri=redirect_uri)

        try:
            request_manager.add_request(
                client_id=client_id,
                redirect_uri=redirect_uri,
                response_type=response_type,
                scope=scope,
                code_challenge_method=code_challenge_method,
                code_challenge=code_challenge,
                authorization_details=authorization_details,
                session_id=session_id,
                state=state,
                issuer_state=issuer_state,
            )
        except Exception as e:
            current_app.logger.error(f"Error adding request: {e}")
            return jsonify({"error": "Failed to process request"}), 500

        authorization_args = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
        }
        if scope:
            authorization_args["scope"] = scope
        if authorization_details:
            authorization_args["authorization_details"] = authorization_details
        if code_challenge and code_challenge_method:
            authorization_args["code_challenge"] = code_challenge
            authorization_args["code_challenge_method"] = code_challenge_method
        if state:
            authorization_args["state"] = state

    try:

        response = service_endpoint(
            current_app.server.get_endpoint("authorization"),
            get_args=authorization_args,
        )

        _response = json.loads(response.get_data(as_text=True))

        jws = _response.get("jws")

        redirect_url = (
            current_app.authorization_redirect_url
            + "?token="
            + jws
            + "&session_id="
            + session_id
        )
        if scope:
            redirect_url += "&scope=" + urllib.parse.quote(scope)

        if authorization_details:
            encoded_auth_details = urllib.parse.quote(json.dumps(authorization_details))
            redirect_url += "&authorization_details=" + encoded_auth_details

        current_request = request_manager.get_request(session_id=session_id)
        frontend_id = getattr(current_request, "frontend_id", None) if current_request else None

        if frontend_id:
            redirect_url += "&frontend_id=" + urllib.parse.quote(frontend_id)

        # Signed copy of the session id, scope and authorization details:
        # the backend trusts these claims, not the plain query parameters.
        redirect_url += "&session_token=" + session_token(
            session_id=session_id,
            scope=scope,
            authorization_details=authorization_details,
            frontend_id=frontend_id,
        )

        return redirect(redirect_url)

    except requests.exceptions.RequestException as e:
        current_app.logger.error(
            f"Error making internal request to authorization endpoint: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "internal_service_unavailable",
        )
    except Exception as e:
        current_app.logger.error(
            f"Unexpected error during authorization processing: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "unhandled_exception",
        )


@oidc_op_views.route("/pushed_authorization", methods=["POST"])
def par_endpoint():

    # Required parameters
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    response_type = request.form.get("response_type")  # Should be "code" as per OID4VCI

    # Validate required parameters
    if not all([client_id, redirect_uri, response_type]):
        return jsonify({"error": "Missing required parameters"}), 400

    # Optional parameters
    scope = request.form.get("scope")
    code_challenge_method = request.form.get("code_challenge_method")
    code_challenge = request.form.get("code_challenge")
    state = request.form.get("state")
    issuer_state = request.form.get("issuer_state")
    frontend_id = request.form.get("frontend_id")

    # issuer_state comes from the wallet (a credential offer): using it as the
    # session id would let a client choose or overwrite another session.
    session_id = str(uuid4())

    current_app.logger.info(
        f"Session ID: {session_id}, Pushed Authorization Request, Payload: {redact(request.form.to_dict())}"
    )

    authorization_details = None
    if "authorization_details" in request.form:
        try:
            authorization_details = json.loads(request.form["authorization_details"])
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid authorization_details JSON"}), 400

    dynamic_registration(client_id=client_id, redirect_uri=redirect_uri)
    try:
        response = service_endpoint(
            current_app.server.get_endpoint("pushed_authorization")
        )
    except Exception as e:
        current_app.logger.error(
            f"Error accessing pushed_authorization endpoint: {e}", exc_info=True
        )
        abort(
            500,
            description="An internal server error occurred while processing the request.",
        )

    if response.status_code >= 400:
        # Client authentication (e.g. the WIA) or request validation failed.
        current_app.logger.warning(f"Session ID: {session_id}, Pushed Authorization Request rejected")
        return response

    try:
        request_manager.add_request(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
            authorization_details=authorization_details,
            session_id=session_id,
            state=state,
            issuer_state=issuer_state,
        )

        request_manager.update_request_uri(
            session_id=session_id, request_uri=response.json["request_uri"]
        )

        if frontend_id:
            request_manager.update_frontend_id(
                session_id=session_id, frontend_id=frontend_id
            )

    except Exception as e:
        current_app.logger.error(f"Error adding request: {e}")
        return jsonify({"error": "Failed to process request"}), 500

    current_app.logger.info(f", Session ID: {session_id}, Pushed Authorization Response")

    return response


""" @oidc_op_views.route("/token", methods=["GET", "POST"])
def token():
    return service_endpoint(current_app.server.get_endpoint("token")) """


def _allowed_htu():
    """Public token endpoint URLs a DPoP proof may address (``allowed_htu``)."""
    conf = current_app.server.get_context().conf.get("conf") or {}
    return conf.get("add_ons", {}).get("dpop", {}).get("kwargs", {}).get("allowed_htu") or []


def _bind_dpop(response_json, jkt, current_request):
    """Binds the issued access token to the DPoP key, if a proof was sent.

    Args:
        response_json: Token response (updated: ``token_type`` becomes DPoP).
        jkt: Thumbprint of the proof key, or None without a proof.
        current_request: Issuance session.

    Returns:
        None, or an error response when a refresh changes the key.
    """
    bound = getattr(current_request, "dpop_jkt", None)
    if bound and jkt != bound:
        return make_response(
            jsonify({"error": "invalid_dpop_proof", "error_description": "DPoP key differs from the bound key"}), 400
        )
    if jkt and "access_token" in response_json:
        dpop.bindings.bind(response_json["access_token"], jkt, float(response_json.get("expires_in") or 3600))
        current_request.dpop_jkt = jkt
        response_json["token_type"] = "DPoP"
    return None


@oidc_op_views.route("/token", methods=["POST"])
def token():
    req_args = dict([(k, v) for k, v in request.form.items()])

    grant_type = req_args.get("grant_type")
    response = None

    # A DPoP proof binds the tokens to the wallet key (RFC 9449).
    jkt = None
    if "DPoP" in request.headers:
        try:
            jkt = dpop.verify_proof(request.headers["DPoP"], request.method, _allowed_htu())
        except dpop.DPoPError as e:
            current_app.logger.warning(f"Token request rejected: {e}")
            return make_response(
                jsonify({"error": "invalid_dpop_proof", "error_description": "Invalid DPoP proof"}), 400
            )

    if grant_type == "authorization_code":
        code = req_args.get("code")
        if not code:
            return make_response(
                jsonify({"error": "invalid_request", "description": "missing code"}),
                400,
            )

        current_request = request_manager.get_request_by_code(code)
        if current_request is None:
            return make_response(jsonify({"error": "invalid_grant"}), 400)

        session_id = current_request.session_id

        current_app.logger.info(f", Session ID: {session_id}, Token Request")

        # Pass the request form data to service_endpoint for accurate processing
        response_obj = service_endpoint(current_app.server.get_endpoint("token"))

        response_data = response_obj.get_data()

        if response_obj.status_code != 200:
            return make_response(response_data, response_obj.status_code)

        response_json = json.loads(response_data)

        current_app.logger.info(f", Session ID: {session_id}, Token Response issued")

        binding_error = _bind_dpop(response_json, jkt, current_request)
        if binding_error is not None:
            return binding_error

        if "access_token" in response_json:
            request_manager.update_access_token(
                session_id=session_id, access_token=response_json["access_token"]
            )

        if "refresh_token" in response_json:
            request_manager.update_refresh_token(
                session_id=session_id, refresh_token=response_json["refresh_token"]
            )

        return jsonify(response_json)  # Return as JSON

    elif grant_type == "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        pre_authorized_code_from_request = req_args.get("pre-authorized_code")
        tx_code_from_request = req_args.get("tx_code")

        if not pre_authorized_code_from_request:
            return make_response(
                jsonify(
                    {
                        "error": "invalid_request",
                        "description": "missing pre-authorized_code",
                    }
                ),
                400,
            )

        if not tx_code_from_request:
            return make_response(
                jsonify({"error": "invalid_request", "description": "missing tx_code"}),
                400,
            )

        current_request = request_manager.get_request_by_preauth_code_ref(
            pre_authorized_code_from_request
        )

        if (
            current_request is None
            or current_request.pre_authorized_code_ref != pre_authorized_code_from_request
            or request_manager.preauth_code_expired(current_request)
        ):
            error_message = {
                "error": "invalid_grant",
                "description": "invalid or expired pre-authorized_code",
            }
            return make_response(jsonify(error_message), 400)

        session_id = current_request.session_id

        if not secrets.compare_digest(str(tx_code_from_request), str(current_request.tx_code)):
            revoked = request_manager.register_tx_code_failure(current_request)
            error_message = {
                "error": "invalid_grant",
                "description": "pre-authorized_code revoked after too many attempts"
                if revoked
                else "invalid tx_code",
            }
            return make_response(jsonify(error_message), 400)

        # Construct payload for the internal authorization_code flow
        internal_payload = {
            "grant_type": "authorization_code",
            "code": current_request.pre_authorized_code,
            "redirect_uri": "preauth",  # This should be a consistent value for internal use
            "client_id": "eudiw-abca",
            "state": "vFs5DfvJqoyHj7_dZs2JbdklePg6pMLsUHHmVIfobRw",
        }

        # Make an internal request to the actual OIDC token endpoint via service_endpoint
        # We're simulating calling the OIDC provider's token endpoint directly
        # with the "authorization_code" grant type.
        # The code belongs to the internal pre-authorized client, not to the
        # wallet's client_id: its wallet attestation is still fully verified.
        response_obj = service_endpoint(
            current_app.server.get_endpoint("token"),
            get_args=internal_payload,
            parse_kwargs={"skip_client_id_check": True},
        )

        response_data = response_obj.get_data()

        if response_obj.status_code != 200:
            return make_response(response_data, response_obj.status_code)

        response_json = json.loads(response_data)  # Ensure it's JSON from get_data()

        request_manager.revoke_preauth_code(current_request)
        current_app.logger.info(f", Session ID: {session_id}, Pre-Authorized Token Response issued")

        binding_error = _bind_dpop(response_json, jkt, current_request)
        if binding_error is not None:
            return binding_error

        if "access_token" in response_json:
            request_manager.update_access_token(
                session_id=session_id, access_token=response_json["access_token"]
            )
        if "refresh_token" in response_json:
            request_manager.update_refresh_token(
                session_id=session_id, refresh_token=response_json["refresh_token"]
            )
        return jsonify(response_json)  # Return as JSON

    elif grant_type == "refresh_token":
        refresh_token = req_args.get("refresh_token")
        if not refresh_token:
            return make_response(
                jsonify(
                    {"error": "invalid_request", "description": "missing refresh_token"}
                ),
                400,
            )

        current_request = request_manager.get_request_by_refresh_token(
            refresh_token=refresh_token
        )

        if current_request is None:
            error_message = {
                "error": "invalid_grant",
            }
            return make_response(jsonify(error_message), 400)

        session_id = current_request.session_id

        # Pass the request form data to service_endpoint
        response_obj = service_endpoint(current_app.server.get_endpoint("token"))

        response_data = response_obj.get_data()

        if response_obj.status_code != 200:
            return make_response(response_data, response_obj.status_code)

        response_json = json.loads(response_data)

        binding_error = _bind_dpop(response_json, jkt, current_request)
        if binding_error is not None:
            return binding_error

        if "access_token" in response_json:
            request_manager.update_access_token(
                session_id=session_id, access_token=response_json["access_token"]
            )

        if "refresh_token" in response_json:
            request_manager.update_refresh_token(
                session_id=session_id, refresh_token=response_json["refresh_token"]
            )

        current_app.logger.info(f", Session ID: {session_id}, Refresh Token Response issued")

        return jsonify(response_json)  # Return as JSON

    else:
        # For any other grant type or if grant_type is missing
        error_message = {
            "error": "unsupported_grant_type",
            "description": f"The grant type '{grant_type}' is not supported.",
        }

        current_app.logger.info(f"Unsupported Token Request: {request.form.to_dict()}")
        return make_response(jsonify(error_message), 400)


@oidc_op_views.route("/introspection", methods=["POST"])
def introspection_endpoint():
    # Only the issuer backend introspects tokens.
    api_key_error = backend_api_key_error()
    if api_key_error is not None:
        return api_key_error

    response = service_endpoint(current_app.server.get_endpoint("introspection"))
    if response.status_code != 200:
        return response
    body = json.loads(response.get_data(as_text=True))
    jkt = dpop.bindings.jkt(request.form.get("token", ""))
    if body.get("active") and jkt:
        # RFC 9449 section 6.2: the resource server checks the proof key.
        body["cnf"] = {"jkt": jkt}
    result = make_response(jsonify(body), 200)
    result.headers["Cache-Control"] = "no-store"
    return result


@oidc_op_views.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    return service_endpoint(current_app.server.get_endpoint("userinfo"))


@oidc_op_views.route("/session", methods=["GET"])
def session_endpoint():
    return service_endpoint(current_app.server.get_endpoint("session"))


IGNORE = ["cookie", "user-agent"]


def _client_authn_error(err):
    """401 invalid_client: the client (its wallet attestation) did not authenticate."""
    return make_response(
        json.dumps({"error": "invalid_client", "error_description": str(err) or "client authentication failed"}),
        401,
        {"Content-Type": "application/json"},
    )


def service_endpoint(endpoint, get_args=None, parse_kwargs=None):
    """Run an idpy-oidc endpoint on the current request.

    :param get_args: request arguments to use instead of the request's own
    :param parse_kwargs: extra arguments for parse_request, set only by this
        server (e.g. skip_client_id_check for the internal pre-authorized call)
    """
    _log = current_app.logger
    parse_kwargs = parse_kwargs or {}
    _log.info('At the "{}" endpoint'.format(endpoint.name))

    http_info = {
        "headers": {
            k: v for k, v in request.headers.items(lower=True) if k not in IGNORE
        },
        "method": request.method,
        "url": request.url,
        # name is not unique
        "cookie": [{"name": k, "value": v} for k, v in request.cookies.items()],
    }
    _log.debug(f"http_info: {redact(http_info)}")

    if request.method == "GET":
        args_for_parsing = get_args if get_args is not None else request.args.to_dict()

        try:
            req_args = endpoint.parse_request(args_for_parsing, http_info=http_info, **parse_kwargs)
        except (ClientAuthenticationError, UnAuthorizedClient) as err:
            _log.error(err)
            return _client_authn_error(err)
        except Exception as err:
            _log.error(err)
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )
    else:
        if request.data:
            if isinstance(request.data, str):
                req_args = request.data
            else:
                req_args = request.data.decode()
        else:
            req_args = (
                get_args
                if get_args is not None
                else dict([(k, v) for k, v in request.form.items()])
            )
        try:
            req_args = endpoint.parse_request(req_args, http_info=http_info, **parse_kwargs)
        except (ClientAuthenticationError, UnAuthorizedClient) as err:
            _log.warning(f"Client authentication failed at {endpoint.name}: {err}")
            return _client_authn_error(err)
        except Exception as err:
            _log.error(err)
            err_msg = ResponseMessage(
                error="invalid_request", error_description=str(err)
            )
            return make_response(err_msg.to_json(), 400)

    if isinstance(req_args, ResponseMessage) and "error" in req_args:
        _log.info("Error response: {}".format(redact(req_args)))
        _resp = make_response(req_args.to_json(), 400)
        if request.method == "POST":
            _resp.headers["Content-type"] = "application/json"
        return _resp
    try:
        _log.debug("request: {}".format(redact(req_args)))
        if isinstance(endpoint, Token):
            args = endpoint.process_request(
                AccessTokenRequest(**req_args), http_info=http_info
            )
        else:
            args = endpoint.process_request(req_args, http_info=http_info)
    except VerificationError as ve:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
        _resp = Introspection.response_cls(active=False)
        args = {"response_args": _resp}
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
        err_msg = ResponseMessage(error="invalid_request", error_description=str(err))
        return make_response(err_msg.to_json(), 400)

    _log.debug("Response args: {}".format(redact(args)))

    if "redirect_location" in args:
        return redirect(args["redirect_location"])
    if "http_response" in args:
        return make_response(args["http_response"], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@oidc_op_views.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return "bad request!", 400


@oidc_op_views.route("/check_session_iframe", methods=["GET", "POST"])
def check_session_iframe():
    if request.method == "GET":
        req_args = request.args.to_dict()
    else:
        if request.data:
            req_args = json.loads(as_unicode(request.data))
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])

    if req_args:
        _context = current_app.server.get_context()
        # will contain client_id and origin
        if req_args["origin"] != _context.issuer:
            return "error"
        if req_args["client_id"] not in _context.cdb:
            return "error"
        return "OK"

    current_app.logger.debug("check_session_iframe: {}".format(req_args))
    doc = open("templates/check_session_iframe.html").read()
    current_app.logger.debug(f"check_session_iframe response: {doc}")
    return doc


@oidc_op_views.route("/verify_logout", methods=["GET", "POST"])
def verify_logout():
    part = urlparse(current_app.server.get_context().issuer)
    page = render_template(
        "logout.html",
        op=part.hostname,
        do_logout="rp_logout",
        sjwt=request.args["sjwt"],
    )
    return page


@oidc_op_views.route("/rp_logout", methods=["GET", "POST"])
def rp_logout():
    _endp = current_app.server.get_endpoint("session")
    _info = _endp.unpack_signed_jwt(request.form["sjwt"])
    try:
        request.form["logout"]
    except KeyError:
        alla = False
    else:
        alla = True

    _iframes = _endp.do_verified_logout(alla=alla, **_info)

    if _iframes:
        res = render_template(
            "frontchannel_logout.html",
            frames=" ".join(_iframes),
            size=len(_iframes),
            timeout=5000,
            postLogoutRedirectUri=_info["redirect_uri"],
        )
    else:
        res = redirect(_info["redirect_uri"])

        # rohe are you sure that _kakor is the right word? :)
        _kakor = _endp.kill_cookies()
        for cookie in _kakor:
            _add_cookie(res, cookie)

    return res


@oidc_op_views.route("/post_logout", methods=["GET"])
def post_logout():
    page = render_template("post_logout.html")
    return page


# Pre-authorized flow: only the issuer backend may mint codes (X-Api-Key).
@oidc_op_views.route("/preauth_generate", methods=["POST"])
def prea_auth():
    api_key_error = backend_api_key_error()
    if api_key_error is not None:
        return api_key_error

    session_id = str(uuid4())
    current_app.logger.info(f"Session ID: {session_id}, Pre-Auth generate")
    # request_data = request.get_json(silent=True)
    """ if not request_data:
        request_data = {} """

    scope = request.form.get("scope")  # request_data.get("scope")
    authorization_details = None  # request_data.get("authorization_details")

    client_id = "eudiw-abca"
    redirect_uri = "preauth"
    response_type = "code"

    dynamic_registration(client_id=client_id, redirect_uri=redirect_uri)

    authorization_args = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
    }
    if scope:
        authorization_args["scope"] = scope
    if authorization_details:
        authorization_args["authorization_details"] = authorization_details

    try:

        response = service_endpoint(
            current_app.server.get_endpoint("authorization"),
            get_args=authorization_args,
        )

        # Ensure response is what we expect (e.g., has 'data' attribute if it's a Flask Response object)
        if not hasattr(response, "data"):
            current_app.logger.error(
                "Internal service_endpoint did not return expected response object with 'data'."
            )
            return auth_error_redirect(
                authorization_args.get("redirect_uri"),
                "server_error",
                "invalid_internal_response",
            )

        _jws = response.data.decode("utf-8")

        jws = json.loads(_jws)["jws"]

    except requests.exceptions.RequestException as e:
        current_app.logger.error(
            f"Error making internal request to authorization endpoint: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "internal_service_unavailable",
        )
    except Exception as e:
        current_app.logger.error(
            f"Unexpected error during authorization processing: {e}"
        )
        return auth_error_redirect(
            authorization_args.get("redirect_uri"),
            "server_error",
            "unhandled_exception",
        )

    tx_code = 10000 + secrets.randbelow(90000)

    try:
        request_manager.add_request(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            authorization_details=authorization_details,
            session_id=session_id,
            tx_code=tx_code,
        )
    except Exception as e:
        current_app.logger.error(f"Error adding request: {e}")
        return jsonify({"error": "Failed to process request"}), 500

    try:
        authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
            "user"
        )

        username = authn_method.verify(username=session_id)

        auth_args = authn_method.unpack_token(jws)

    except:
        current_app.logger.error(
            "Authorization verification: username or jws_token not found"
        )
        if "jws_token" in request.args:
            return authentication_error_redirect(
                jws_token=request.args.get("jws_token"),
                error="invalid_request",
                error_description="Authentication verification Error",
            )
        else:
            return "Internal Server Error", 500
            # return render_template("misc/500.html", error="Authentication verification Error")

    authz_request = AuthorizationRequest().from_urlencoded(auth_args["query"])

    endpoint = current_app.server.get_endpoint("authorization")

    _session_id = endpoint.create_session(
        authz_request,
        username,
        auth_args["authn_class_ref"],
        auth_args["iat"],
        authn_method,
    )

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    # authz_part2 returns a dict and reports errors inside response_args
    response_dict = args.get("response_args").to_dict()

    if "error" in response_dict:
        current_app.logger.error(
            f"authz_part2 returned error for pre-auth session {username}: {response_dict}"
        )
        return make_response(json.dumps(response_dict), 400)

    request_manager.update_pre_authorized_code(
        session_id=username, pre_authorized_code=response_dict["code"]
    )

    preauth_code_ref = str(uuid4())

    request_manager.update_pre_authorized_code_ref(
        session_id=username, pre_authorized_code_ref=preauth_code_ref
    )

    response = {
        "preauth_code": preauth_code_ref,
        "session_id": session_id,
        "tx_code": tx_code,
    }
    return jsonify(response)
