import json

import httpx

from util.request.BiliRequest import BiliRequest


def _response(status_code: int, url: str, *, headers=None, text: str = ""):
    return httpx.Response(
        status_code,
        text=text,
        headers=headers,
        request=httpx.Request("POST", url),
        extensions={"http_version": b"HTTP/2"},
    )


def test_request_error_sidecar_records_412_context(monkeypatch, tmp_path):
    monkeypatch.setenv("BTB_ERROR_SIDECAR_DIR", str(tmp_path))
    request = BiliRequest(cookies=[])
    target_url = "https://show.bilibili.com/api/ticket/order/createV2"
    response_412 = _response(
        412,
        target_url,
        headers={"set-cookie": "other=value; Path=/"},
        text="challenge",
    )

    monkeypatch.setattr(request, "_h2_send", lambda *args, **kwargs: response_412)

    response = request.post(target_url, data={"project_id": 1}, isJson=True)

    assert response is response_412
    sidecar_files = list(tmp_path.glob("bili_request_errors_*.jsonl"))
    assert len(sidecar_files) == 1
    record = json.loads(sidecar_files[0].read_text(encoding="utf-8").splitlines()[0])
    assert record["event"] == "http_response"
    assert record["stage"] == "initial_response"
    assert record["request"]["method"] == "POST"
    assert record["request"]["body"] == {"project_id": 1}
    assert record["response"]["status_code"] == 412
    assert record["response"]["body"]["text"] == "challenge"
    assert {"name": "set-cookie", "value": "other=value; Path=/"} in record[
        "response"
    ]["headers"]


def test_request_error_sidecar_write_failure_does_not_change_result(
    monkeypatch,
    tmp_path,
):
    sidecar_path = tmp_path / "not-a-directory"
    sidecar_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("BTB_ERROR_SIDECAR_DIR", str(sidecar_path))
    request = BiliRequest(cookies=[])
    target_url = "https://show.bilibili.com/api/ticket/order/createV2"
    response_412 = _response(412, target_url)

    monkeypatch.setattr(request, "_h2_send", lambda *args, **kwargs: response_412)

    response = request.post(target_url, data={}, isJson=True)

    assert response is response_412
    assert request.request_count == 1
