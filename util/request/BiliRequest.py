import base64
import hashlib
import json
import secrets
import time
from http.cookies import SimpleCookie

import loguru
import requests
from requests import Response
from util.Constant import H2_LIMITS, H2_TIMEOUT
from util.request.BrowerState import (
    BrowserFingerprintState,
    build_headers_from_browser_state,
    finalize_device_id,
    generate_browser_fingerprint_state,
)
from util.request.CookieManager import CookieManager
from util.request.ErrorSidecar import BiliRequestErrorSidecar
from util.request.exceptions import BiliConnectionError, BiliRateLimitError
from util.proxy.ProxyManager import ProxyManager


class BiliRequest:
    _CHALLENGE_COOKIE = "X-BILI-SEC-TOKEN"
    _CHALLENGE_CHECK_URL = "https://security.bilibili.com/th/captcha/cc/check"
    _CHALLENGE_CACHE_EXPIRY_SKEW_SECONDS = 300

    def __init__(
        self,
        headers=None,
        cookies=None,
        cookies_config_path=None,
        proxy: str = "none",
        browser_state: BrowserFingerprintState | None = None,
        proxy_failure_threshold: int = 2,
        proxy_cooldown_seconds: float = 180.0,
    ):
        self.browser_state = browser_state or generate_browser_fingerprint_state()
        self.deviceId = finalize_device_id(secrets.token_hex(16))
        self.session = requests.Session()
        self.proxy_manager = ProxyManager(
            proxy,
            failure_threshold=proxy_failure_threshold,
            cooldown_seconds=proxy_cooldown_seconds,
        )
        self.cookieManager = CookieManager(cookies_config_path, cookies)
        self.headers = build_headers_from_browser_state(
            self.browser_state,
            base_headers=headers,
            referer="https://show.bilibili.com/",
            content_type="application/x-www-form-urlencoded",
        )
        self.request_count = 0  # 记录请求次数
        self.proxy_manager.apply_to_session(self.session)
        self._h2_client = None
        self._bili_sec_token_cache: str | None = None
        self._error_sidecar = BiliRequestErrorSidecar()
        self.createTime = int(time.time() * 1000)

    def _rotate_proxy(self, reason: str) -> bool:
        if not self.proxy_manager.rotate():
            return False
        self.proxy_manager.apply_to_session(self.session)
        self._invalidate_h2_client()
        return True

    def _invalidate_h2_client(self):
        if self._h2_client is None:
            return
        try:
            self._h2_client.close()
        except Exception:
            pass
        self._h2_client = None

    def get_user_agent(self) -> str:
        return self.headers.get("user-agent", "")

    def snapshot_proxy_state(self) -> int:
        return self.proxy_manager.snapshot()

    def restore_proxy_state(self, state: int) -> None:
        self.proxy_manager.restore(state)
        self.proxy_manager.apply_to_session(self.session)
        self._invalidate_h2_client()

    def clear_request_count(self):
        self.request_count = 0

    def get(self, url, data=None, isJson=False):
        return self._request("get", url, data=data, isJson=isJson)

    def switch_proxy(self):
        return self._rotate_proxy("手动切换代理")

    def post(self, url, data=None, isJson=False):
        return self._request("post", url, data=data, isJson=isJson)

    def current_proxy_display(self) -> str:
        return self.proxy_manager.current_proxy_display

    def current_proxy_status(self) -> str:
        return self.proxy_manager.current_proxy_status()

    def proxy_pool_status(self) -> str:
        return self.proxy_manager.proxy_pool_status()

    def has_available_proxy(self) -> bool:
        return self.proxy_manager.has_available_proxy()

    def is_current_proxy_available(self) -> bool:
        return self.proxy_manager.is_current_proxy_available()

    def ensure_active_proxy(self) -> bool:
        if not self.proxy_manager.ensure_current_available():
            return False
        self.proxy_manager.apply_to_session(self.session)
        return True

    def mark_current_proxy_failure(self, reason: str) -> bool:
        return self.proxy_manager.mark_current_failure(reason)

    def mark_current_proxy_success(self) -> None:
        self.proxy_manager.mark_current_success()

    def describe_non_json_response(
        self, response: Response, body_limit: int = 300
    ) -> str:
        content_type = response.headers.get("Content-Type", "未知")
        body = response.text or ""
        body = body.replace("\r", "\\r").replace("\n", "\\n")
        if len(body) > body_limit:
            body = body[:body_limit] + "..."
        if not body:
            body = "<empty>"
        return (
            f"status={response.status_code}, "
            f"content_type={content_type}, "
            f"url={response.url}, "
            f"body_preview={body}"
        )

    def _build_h2_client(self):
        import httpx

        proxies = self.session.proxies or {}
        proxy = proxies.get("https") or proxies.get("http") or None
        verify = (
            self.session.verify
            if isinstance(self.session.verify, (bool, str))
            else True
        )
        return httpx.Client(
            http2=True,
            verify=verify,
            proxy=proxy,
            timeout=httpx.Timeout(**H2_TIMEOUT),
            limits=httpx.Limits(**H2_LIMITS),
            headers={
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "connection": "keep-alive",
                "user-agent": self.headers.get("user-agent", ""),
            },
        )

    def _sync_h2_cookies(self, client) -> None:
        for cookie in self.cookieManager.get_cookies(force=True) or []:
            name = cookie.get("name")
            value = cookie.get("value")
            if name and value is not None:
                client.cookies.set(name, value, domain=".bilibili.com")
        if cached_token := self._get_cached_bili_sec_token():
            client.cookies.set(
                self._CHALLENGE_COOKIE,
                cached_token,
                domain=".bilibili.com",
            )

    def prewarm_h2_connection(self, url: str) -> None:
        import httpx

        if self._h2_client is None:
            self._h2_client = self._build_h2_client()
        client = self._h2_client
        client.headers["user-agent"] = self.headers.get("user-agent", "")
        self._sync_h2_cookies(client)
        try:
            client.head(url)
        except httpx.HTTPError:
            pass

    def _h2_send(self, method: str, url, data=None, isJson=False, headers=None):
        if self._h2_client is None:
            self._h2_client = self._build_h2_client()
        client = self._h2_client
        client.headers["user-agent"] = self.headers.get("user-agent", "")
        self._sync_h2_cookies(client)
        if method.lower() == "post":
            return (
                client.post(url, json=data, headers=headers)
                if isJson
                else client.post(url, data=data, headers=headers)
            )
        return client.get(url, params=data, headers=headers)

    def _send_with_h2_recovery(
        self,
        method: str,
        url,
        data=None,
        isJson=False,
        headers=None,
    ):
        import httpx

        for attempt in range(2):
            try:
                return self._h2_send(
                    method,
                    url,
                    data=data,
                    isJson=isJson,
                    headers=headers,
                )
            except httpx.TimeoutException as exc:
                self._invalidate_h2_client()
                if attempt >= 1:
                    self._record_request_exception(
                        "h2_timeout",
                        method,
                        url,
                        data=data,
                        isJson=isJson,
                        headers=headers,
                        exc=exc,
                        attempt=attempt + 1,
                    )
                    raise BiliConnectionError(
                        "网络请求超时：服务器响应过慢，请稍后重试",
                        cause=exc,
                    ) from exc
                loguru.logger.warning("HTTP 请求超时，已重建连接后重试: {}", exc)
            except httpx.LocalProtocolError as exc:
                self._invalidate_h2_client()
                if attempt >= 1:
                    self._record_request_exception(
                        "h2_protocol_error",
                        method,
                        url,
                        data=data,
                        isJson=isJson,
                        headers=headers,
                        exc=exc,
                        attempt=attempt + 1,
                    )
                    raise BiliConnectionError(
                        "网络连接异常：HTTP/2 连接已断开，重试后仍失败，请稍后再试",
                        cause=exc,
                    ) from exc
                loguru.logger.warning("HTTP/2 连接状态异常，已重建连接后重试: {}", exc)

    def _strip_bili_sec_token_prefix(self, token: str | None) -> str | None:
        if not token:
            return None
        token = str(token).strip()
        if not token:
            return None
        return token.split(",", 1)[-1]

    def _decode_bili_sec_token(self, token: str) -> dict:
        jwt_token = self._strip_bili_sec_token_prefix(token)
        if not jwt_token:
            raise ValueError("empty bili challenge token")
        parts = jwt_token.split(".")
        if len(parts) < 2:
            raise ValueError("invalid bili challenge token")
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode((payload + padding).encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid bili challenge payload")
        return data

    def _is_bili_sec_token_expired(self, token: str) -> bool:
        try:
            expires_at = float(self._decode_bili_sec_token(token).get("exp", 0))
        except Exception:
            return True
        return expires_at - time.time() < self._CHALLENGE_CACHE_EXPIRY_SKEW_SECONDS

    def _get_cached_bili_sec_token(self) -> str | None:
        token = self._bili_sec_token_cache
        if not token:
            return None
        if self._is_bili_sec_token_expired(token):
            self._bili_sec_token_cache = None
            return None
        return token

    def _set_bili_sec_token(self, token: str, *, cache: bool = True) -> None:
        if cache:
            self._bili_sec_token_cache = token
        self.session.cookies.set(
            self._CHALLENGE_COOKIE,
            token,
            domain=".bilibili.com",
        )
        if self._h2_client is not None:
            self._h2_client.cookies.set(
                self._CHALLENGE_COOKIE,
                token,
                domain=".bilibili.com",
            )

    def _extract_bili_sec_token(self, response) -> str | None:
        try:
            token = response.cookies.get(self._CHALLENGE_COOKIE)
            if token:
                return token
        except Exception:
            pass

        set_cookie_headers = []
        try:
            set_cookie_headers = response.headers.get_list("set-cookie")
        except AttributeError:
            header_value = response.headers.get("set-cookie")
            if header_value:
                set_cookie_headers = [header_value]

        for header_value in set_cookie_headers:
            cookie = SimpleCookie()
            try:
                cookie.load(header_value)
            except Exception:
                continue
            morsel = cookie.get(self._CHALLENGE_COOKIE)
            if morsel is not None:
                return morsel.value

        if self._h2_client is not None:
            try:
                return self._h2_client.cookies.get(self._CHALLENGE_COOKIE)
            except Exception:
                return None
        return None

    def bili_challenge_result(self, data: dict, limit: int = 5_000_000) -> str | None:
        if int(data.get("type", 0) or 0) != 1:
            return None
        q = data.get("q")
        expected_hash = data.get("r")
        if not isinstance(q, str) or not isinstance(expected_hash, str):
            return None
        for value in range(limit):
            result = str(value)
            digest = hashlib.sha256((q + result).encode()).hexdigest()
            if digest == expected_hash:
                return result
        return None

    def _submit_bili_challenge(self, token: str) -> str | None:
        try:
            token_data = self._decode_bili_sec_token(token)
            result = self.bili_challenge_result(token_data)
        except Exception as exc:
            loguru.logger.warning("解析 B 站 412 challenge 失败: {}", exc)
            return None
        if result is None:
            loguru.logger.warning("未能生成 B 站 412 challenge 结果")
            return None

        response = self._send_with_h2_recovery(
            "post",
            self._CHALLENGE_CHECK_URL,
            data={
                "token": self._strip_bili_sec_token_prefix(token),
                "result": result,
            },
            isJson=False,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://www.bilibili.com",
                "referer": "https://www.bilibili.com/",
            },
        )
        if response.status_code >= 400:
            loguru.logger.warning(
                "提交 B 站 412 challenge 失败: HTTP {}",
                response.status_code,
            )
            return None
        try:
            payload = response.json()
        except Exception as exc:
            loguru.logger.warning("提交 B 站 412 challenge 后响应非 JSON: {}", exc)
            return None

        if int(payload.get("code", -1)) != 0:
            loguru.logger.warning(
                "提交 B 站 412 challenge 被拒绝: {}",
                payload.get("message", payload),
            )
            return None
        new_token = payload.get("message")
        return str(new_token).strip() if new_token else None

    def _recover_from_bili_412(self, response, method: str, url, data=None, isJson=False):
        challenge_token = self._extract_bili_sec_token(response)
        if not challenge_token:
            return None

        if cached_token := self._get_cached_bili_sec_token():
            self._set_bili_sec_token(cached_token, cache=False)
            retried = self._send_with_h2_recovery(
                method,
                url,
                data=data,
                isJson=isJson,
            )
            if retried.status_code != 412:
                loguru.logger.info("B 站 412 challenge 使用缓存 token 恢复")
                return retried

        new_token = self._submit_bili_challenge(challenge_token)
        if not new_token:
            return None
        self._set_bili_sec_token(new_token, cache=True)
        loguru.logger.info("B 站 412 challenge 已完成，重试原请求")
        return self._send_with_h2_recovery(
            method,
            url,
            data=data,
            isJson=isJson,
        )

    def _request_headers_snapshot(self, headers=None) -> dict:
        request_headers = dict(self.headers)
        if headers:
            request_headers.update(headers)
        return request_headers

    def _record_error_response(
        self,
        stage: str,
        response,
        method: str,
        url,
        *,
        data=None,
        isJson=False,
        headers=None,
    ) -> None:
        self._error_sidecar.record_response(
            stage=stage,
            method=method,
            url=str(url),
            data=data,
            is_json=isJson,
            request_headers=self._request_headers_snapshot(headers),
            response=response,
        )

    def _record_request_exception(
        self,
        stage: str,
        method: str,
        url,
        *,
        data=None,
        isJson=False,
        headers=None,
        exc: BaseException,
        attempt: int,
    ) -> None:
        self._error_sidecar.record_exception(
            stage=stage,
            method=method,
            url=str(url),
            data=data,
            is_json=isJson,
            request_headers=self._request_headers_snapshot(headers),
            exc=exc,
            attempt=attempt,
        )

    def _request(self, method: str, url, data=None, isJson=False):
        response = self._send_with_h2_recovery(
            method,
            url,
            data=data,
            isJson=isJson,
        )
        if response.status_code >= 400:
            self._record_error_response(
                "initial_response",
                response,
                method,
                url,
                data=data,
                isJson=isJson,
            )

        if response.status_code == 412:
            initial_response = response
            recovered = self._recover_from_bili_412(
                response,
                method,
                url,
                data=data,
                isJson=isJson,
            )
            if recovered is not None:
                response = recovered
                if response is not initial_response and response.status_code >= 400:
                    self._record_error_response(
                        "recovered_response",
                        response,
                        method,
                        url,
                        data=data,
                        isJson=isJson,
                    )
            if response.status_code == 412:
                self.request_count += 1
                return response
        if response.status_code == 429:
            raise BiliRateLimitError(
                f"请求被限流(HTTP 429): {response.url}",
                response=response,
            )

        response.raise_for_status()
        self.clear_request_count()
        self.mark_current_proxy_success()
        if response.json().get("msg", "") == "请先登录":
            raise RuntimeError("当前未登录，请重新登陆")
        return response

    def get_request_name(self):
        try:
            if not self.cookieManager.have_cookies():
                loguru.logger.warning("获取用户名失败，请重新登录")
                return "未登录"
            result = self.get("https://api.bilibili.com/x/web-interface/nav").json()
            return result["data"]["uname"]
        except Exception:
            return "未登录"
