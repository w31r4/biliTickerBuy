import base64
import hashlib
import json
import time

import httpx

from util.request.BiliRequest import BiliRequest


def _base64url_json(data: dict) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode("utf-8")
    )
    return encoded.decode("ascii").rstrip("=")


def _challenge_token(result: str = "7") -> str:
    q = "btb-test:"
    return ".".join(
        (
            _base64url_json({"alg": "HS256", "typ": "JWT"}),
            _base64url_json(
                {
                    "exp": int(time.time()) + 3600,
                    "type": 1,
                    "q": q,
                    "r": hashlib.sha256((q + result).encode()).hexdigest(),
                }
            ),
            "signature",
        )
    )


def _response(status_code: int, url: str, *, json_data=None, headers=None):
    return httpx.Response(
        status_code,
        json=json_data,
        headers=headers,
        request=httpx.Request("POST", url),
    )


def test_request_solves_bili_412_challenge_and_retries(monkeypatch):
    request = BiliRequest(cookies=[])
    target_url = "https://show.bilibili.com/api/ticket/order/createV2"
    challenge_token = _challenge_token(result="7")
    new_token = _challenge_token(result="9")
    calls = []

    def fake_h2_send(method, url, data=None, isJson=False, headers=None):
        calls.append(
            {
                "method": method,
                "url": url,
                "data": data,
                "isJson": isJson,
                "headers": headers,
            }
        )
        if url == request._CHALLENGE_CHECK_URL:
            assert data == {"token": challenge_token, "result": "7"}
            assert headers["origin"] == "https://www.bilibili.com"
            return _response(
                200,
                url,
                json_data={"code": 0, "message": f"v3,{new_token}"},
            )
        if len([call for call in calls if call["url"] == target_url]) == 1:
            return _response(
                412,
                target_url,
                headers={"set-cookie": f"X-BILI-SEC-TOKEN=v3,{challenge_token}; Path=/"},
            )
        return _response(200, target_url, json_data={"msg": "", "data": {"ok": True}})

    monkeypatch.setattr(request, "_h2_send", fake_h2_send)

    response = request.post(target_url, data={"project_id": 1}, isJson=True)

    assert response.status_code == 200
    assert response.json()["data"] == {"ok": True}
    assert request.request_count == 0
    assert request._bili_sec_token_cache == f"v3,{new_token}"
    assert [call["url"] for call in calls] == [
        target_url,
        request._CHALLENGE_CHECK_URL,
        target_url,
    ]


def test_request_preserves_412_when_challenge_token_is_missing(monkeypatch):
    request = BiliRequest(cookies=[])
    target_url = "https://show.bilibili.com/api/ticket/order/createV2"
    response_412 = _response(412, target_url)

    monkeypatch.setattr(request, "_h2_send", lambda *args, **kwargs: response_412)

    response = request.post(target_url, data={}, isJson=True)

    assert response is response_412
    assert request.request_count == 1
