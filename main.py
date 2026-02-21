"""
AstrBot OIDC 登录插件

用于网站 OIDC 登录插件，让支持 OIDC 登录的程序支持 QQ 群聊/私聊登录。

作者: 初叶🍂竹叶-Furry控
版本: v1.0.2
"""

import asyncio
import json
import os
import random
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urljoin

from aiohttp import web

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register


@dataclass
class AuthSession:
    """OIDC 认证会话数据类"""

    session_id: str
    code: str
    state: str
    redirect_uri: str
    created_at: float
    client_id: str = ""
    verified: bool = False
    verified_user_id: Optional[str] = None
    user_info: dict = field(default_factory=dict)


@dataclass
class VerifyCode:
    """验证码数据类"""

    code: str
    session_id: str
    created_at: float
    used: bool = False


class ConfigManager:
    """Web 配置管理器

    管理插件的 Web 端配置，包括验证码设置、主题设置等。
    数据存储在 AstrBot data 目录下，防止更新/重装插件时数据丢失。
    """

    def __init__(self, plugin):
        self.plugin = plugin
        # 数据存储在 AstrBot data 目录下，防止更新/重装插件时数据丢失
        self.data_dir = os.path.join(os.getcwd(), "data", "chuyeoidc")
        os.makedirs(self.data_dir, exist_ok=True)
        self.config_file = os.path.join(self.data_dir, "web_config.json")
        self._web_config: dict = {}
        self._load_config()

    def _load_config(self):
        default_config = {
            "enable_group_verify": True,
            "enable_private_verify": True,
            "verify_group_id": "",
            "code_expire_seconds": 300,
            "code_length": 6,
            "theme_color": "#4f46e5",
            "icon_url": "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
            "favicon_url": "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        }

        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
                    logger.info("Web配置加载成功")
            except Exception as e:
                logger.error(f"加载Web配置失败: {e}")

        self._web_config = default_config

    def save_config(self):
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self._web_config, f, ensure_ascii=False, indent=2)
            logger.info("Web配置保存成功")
            return True
        except Exception as e:
            logger.error(f"保存Web配置失败: {e}")
            return False

    def get(self, key: str, default=None):
        return self._web_config.get(key, default)

    def set(self, key: str, value):
        self._web_config[key] = value

    def update(self, data: dict):
        self._web_config.update(data)
        return self.save_config()

    def get_all(self) -> dict:
        return self._web_config.copy()


class ClientManager:
    """OIDC 客户端管理器

    管理 OIDC 客户端（应用）的注册信息，包括 Client ID、Client Secret 等。
    数据存储在 AstrBot data 目录下，防止更新/重装插件时数据丢失。
    """

    def __init__(self):
        # 数据存储在 AstrBot data 目录下，防止更新/重装插件时数据丢失
        self.data_dir = os.path.join(os.getcwd(), "data", "chuyeoidc")
        os.makedirs(self.data_dir, exist_ok=True)
        self.clients_file = os.path.join(self.data_dir, "clients.json")
        self._clients: dict[str, dict] = {}
        self._load_clients()

    def _load_clients(self):
        if os.path.exists(self.clients_file):
            try:
                with open(self.clients_file, "r", encoding="utf-8") as f:
                    self._clients = json.load(f)
                    logger.info(
                        f"OIDC客户端配置加载成功，共 {len(self._clients)} 个客户端"
                    )
            except Exception as e:
                logger.error(f"加载OIDC客户端配置失败: {e}")
                self._clients = {}
        else:
            self._clients = {}

    def _save_clients(self):
        try:
            with open(self.clients_file, "w", encoding="utf-8") as f:
                json.dump(self._clients, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"保存OIDC客户端配置失败: {e}")
            return False

    def get_client(self, client_id: str) -> Optional[dict]:
        return self._clients.get(client_id)

    def verify_client(self, client_id: str, client_secret: str) -> bool:
        client = self._clients.get(client_id)
        if not client:
            return False
        return client.get("client_secret") == client_secret

    def add_client(
        self,
        client_id: str,
        client_secret: str,
        name: str = "",
        home_url: str = "",
        redirect_url: str = "",
    ) -> bool:
        if client_id in self._clients:
            return False
        self._clients[client_id] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "name": name or client_id,
            "home_url": home_url,
            "redirect_url": redirect_url,
            "created_at": time.time(),
        }
        return self._save_clients()

    def update_client(
        self,
        client_id: str,
        client_secret: str = None,
        name: str = None,
        home_url: str = None,
        redirect_url: str = None,
    ) -> bool:
        if client_id not in self._clients:
            return False
        if client_secret is not None:
            self._clients[client_id]["client_secret"] = client_secret
        if name is not None:
            self._clients[client_id]["name"] = name
        if home_url is not None:
            self._clients[client_id]["home_url"] = home_url
        if redirect_url is not None:
            self._clients[client_id]["redirect_url"] = redirect_url
        return self._save_clients()

    def delete_client(self, client_id: str) -> bool:
        if client_id not in self._clients:
            return False
        del self._clients[client_id]
        return self._save_clients()

    def get_all_clients(self) -> dict:
        return self._clients.copy()

    def generate_client_id(self) -> str:
        return f"client_{secrets.token_urlsafe(8)}"

    def generate_client_secret(self) -> str:
        return secrets.token_urlsafe(32)

    def generate_client_name(self) -> str:
        chars = string.ascii_letters + string.digits
        return f"OIDC_{''.join(random.choices(chars, k=5))}"


class OIDCServer:
    """OIDC 服务端核心类

    处理 OIDC 协议相关的所有逻辑，包括：
    - 认证会话管理
    - 验证码生成和验证
    - Access Token 生成和验证
    - 用户信息获取
    """

    def __init__(
        self, plugin, config_manager: ConfigManager, client_manager: ClientManager
    ):
        self.plugin = plugin
        self.config_manager = config_manager
        self.client_manager = client_manager
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.sessions: dict[str, AuthSession] = {}
        self.verify_codes: dict[str, VerifyCode] = {}
        self.access_tokens: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    def _get_config(self, key: str, default=None):
        return self.plugin._get_config(key, default)

    def _get_web_config(self, key: str, default=None):
        return self.config_manager.get(key, default)

    def _generate_code(self, length: int = 6) -> str:
        return "".join(random.choices(string.digits, k=length))

    def _generate_token(self) -> str:
        return secrets.token_urlsafe(32)

    async def create_auth_session(
        self, redirect_uri: str, state: str, client_id: str = ""
    ) -> tuple[str, str]:
        session_id = str(uuid.uuid4())
        code_length = self._get_web_config("code_length", 6)
        verify_code = self._generate_code(code_length)

        logger.info(f"创建认证会话: session_id={session_id}, verify_code={verify_code}")

        async with self._lock:
            session = AuthSession(
                session_id=session_id,
                code=verify_code,
                state=state,
                redirect_uri=redirect_uri,
                created_at=time.time(),
                client_id=client_id,
            )
            self.sessions[session_id] = session
            self.verify_codes[verify_code] = VerifyCode(
                code=verify_code, session_id=session_id, created_at=time.time()
            )
            logger.info(
                f"会话已存储: sessions count={len(self.sessions)}, verify_codes count={len(self.verify_codes)}"
            )

        return session_id, verify_code

    async def verify_code_submit(
        self, code: str, user_id: str, user_info: dict = None
    ) -> tuple[bool, str]:
        expire_seconds = self._get_web_config("code_expire_seconds", 300)

        async with self._lock:
            if code not in self.verify_codes:
                logger.warning(
                    f"验证码不存在: {code}, 已有验证码: {list(self.verify_codes.keys())}"
                )
                return False, "验证码不存在"

            verify_code = self.verify_codes[code]

            if verify_code.used:
                return False, "验证码已使用"

            if time.time() - verify_code.created_at > expire_seconds:
                del self.verify_codes[code]
                if verify_code.session_id in self.sessions:
                    del self.sessions[verify_code.session_id]
                return False, "验证码已过期"

            verify_code.used = True
            session = self.sessions.get(verify_code.session_id)
            logger.info(
                f"验证码提交: session_id={verify_code.session_id}, session存在={session is not None}, sessions keys={list(self.sessions.keys())}"
            )
            if session:
                session.verified = True
                session.verified_user_id = user_id
                session.user_info = user_info or {"id": user_id, "name": user_id}
                logger.info(
                    f"验证成功: session {verify_code.session_id} 已标记为 verified=True, user_info={session.user_info}"
                )
            else:
                logger.error(f"Session不存在: session_id={verify_code.session_id}")

            return True, verify_code.session_id

    async def get_session(self, session_id: str) -> Optional[AuthSession]:
        logger.info(
            f"get_session: session_id={session_id}, sessions count={len(self.sessions)}, keys={list(self.sessions.keys())[:5]}"
        )
        return self.sessions.get(session_id)

    async def exchange_code(self, code: str, client_id: str = "") -> Optional[dict]:
        logger.info(f"exchange_code: code={code}, client_id={client_id}")
        async with self._lock:
            session = None
            for s in self.sessions.values():
                logger.info(
                    f"检查session: session.code={s.code}, verified={s.verified}"
                )
                if s.code == code and s.verified:
                    session = s
                    break

            if not session:
                logger.warning(f"未找到匹配的session: code={code}")
                return None

            if client_id and session.client_id and session.client_id != client_id:
                logger.warning(
                    f"client_id不匹配: session.client_id={session.client_id}, 请求client_id={client_id}"
                )
                return None

            access_token = self._generate_token()
            id_token = self._generate_token()

            token_data = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token,
                "user_id": session.verified_user_id,
                "user_info": session.user_info,
            }
            self.access_tokens[access_token] = token_data
            self.access_tokens[id_token] = token_data

            logger.info(
                f"Token交换成功: access_token={access_token[:20]}..., user_info={session.user_info}"
            )
            return token_data

    async def get_user_info(self, token: str) -> Optional[dict]:
        result = self.access_tokens.get(token)
        logger.info(
            f"get_user_info: token={token[:20] if token else 'None'}..., found={result is not None}, data={result}"
        )
        return result

    async def cleanup_expired(self):
        expire_seconds = self._get_web_config("code_expire_seconds", 300)
        current_time = time.time()

        async with self._lock:
            expired_codes = [
                code
                for code, vc in self.verify_codes.items()
                if current_time - vc.created_at > expire_seconds
            ]
            for code in expired_codes:
                vc = self.verify_codes.pop(code, None)
                if vc and vc.session_id in self.sessions:
                    del self.sessions[vc.session_id]

            expired_tokens = [
                token
                for token, data in self.access_tokens.items()
                if current_time - data.get("created_at", current_time) > 3600
            ]
            for token in expired_tokens:
                del self.access_tokens[token]

        if expired_codes or expired_tokens:
            logger.debug(
                f"清理过期数据: {len(expired_codes)} 个验证码, {len(expired_tokens)} 个令牌"
            )


class WebHandler:
    """Web 请求处理器

    处理所有 HTTP 请求，包括：
    - OIDC 端点（发现文档、授权、令牌、用户信息）
    - Web 管理后台页面和 API
    - 验证码输入页面
    """

    def __init__(
        self,
        plugin,
        oidc_server: OIDCServer,
        config_manager: ConfigManager,
        client_manager: ClientManager,
    ):
        self.plugin = plugin
        self.oidc_server = oidc_server
        self.config_manager = config_manager
        self.client_manager = client_manager
        self.sessions: dict[str, dict] = {}

    def _get_config(self, key: str, default=None):
        return self.plugin._get_config(key, default)

    def _get_web_config(self, key: str, default=None):
        return self.config_manager.get(key, default)

    def _check_password_default(self) -> bool:
        username = self._get_config("web_username", "yeoidc")
        password = self._get_config("web_password", "yeoidc")
        return username == "yeoidc" and password == "yeoidc"

    def _verify_login(self, username: str, password: str) -> bool:
        config_username = self._get_config("web_username", "yeoidc")
        config_password = self._get_config("web_password", "yeoidc")
        return username == config_username and password == config_password

    def _generate_session_token(self) -> str:
        return secrets.token_urlsafe(32)

    async def handle_root(self, request: web.Request) -> web.Response:
        if request.method == "OPTIONS":
            response = web.Response()
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = (
                "Content-Type, Authorization"
            )
            return response

        secure_path = self._get_config("secure_path", "chuyeoidc")
        path = request.path.strip("/")

        if path == secure_path:
            return await self.handle_admin(request)
        elif path == f"{secure_path}/login":
            return await self.handle_login(request)
        elif path == f"{secure_path}/api/login":
            return await self.handle_api_login(request)
        elif path == f"{secure_path}/api/logout":
            return await self.handle_api_logout(request)
        elif path == f"{secure_path}/api/config":
            return await self.handle_api_config(request)
        elif path == f"{secure_path}/api/config/save":
            return await self.handle_api_config_save(request)
        elif path == f"{secure_path}/api/sessions":
            return await self.handle_api_sessions(request)
        elif path == f"{secure_path}/api/clients":
            return await self.handle_api_clients(request)
        elif path == f"{secure_path}/api/check_password":
            return await self.handle_api_check_password(request)
        elif path == f"{secure_path}/api/clients/add":
            return await self.handle_api_clients_add(request)
        elif path == f"{secure_path}/api/clients/delete":
            return await self.handle_api_clients_delete(request)
        elif path == "authorize":
            return await self.handle_authorize(request)
        elif path == "token":
            return await self.handle_token(request)
        elif path == "userinfo":
            return await self.handle_userinfo(request)
        elif path == ".well-known/openid-configuration":
            return await self.handle_discovery(request)
        elif path == "verify":
            return await self.handle_verify_page(request)
        elif path == "api/verify":
            return await self.handle_api_verify(request)
        elif path == "api/session/status":
            return await self.handle_api_session_status(request)
        else:
            return web.Response(text="Not Found", status=404)

    async def handle_admin(self, request: web.Request) -> web.Response:
        is_default_password = self._check_password_default()
        theme_color = self._get_web_config("theme_color", "#4f46e5")
        icon_url = self._get_web_config(
            "icon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        favicon_url = self._get_web_config(
            "favicon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )

        html = self._render_admin_page(
            is_default_password, theme_color, icon_url, favicon_url
        )
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def handle_login(self, request: web.Request) -> web.Response:
        theme_color = self._get_web_config("theme_color", "#4f46e5")
        icon_url = self._get_web_config(
            "icon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        favicon_url = self._get_web_config(
            "favicon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        html = self._render_login_page(theme_color, icon_url, favicon_url)
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def handle_api_login(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            username = data.get("username", "")
            password = data.get("password", "")

            if self._check_password_default():
                return web.json_response(
                    {
                        "success": False,
                        "message": "请先在插件管理中修改默认密码后再登录",
                        "is_default_password": True,
                    },
                    status=401,
                )

            if self._verify_login(username, password):
                token = self._generate_session_token()
                self.sessions[token] = {"username": username, "created_at": time.time()}
                return web.json_response({"success": True, "token": token})
            else:
                return web.json_response(
                    {"success": False, "message": "用户名或密码错误"}, status=401
                )
        except Exception as e:
            logger.error(f"登录处理错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_logout(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token in self.sessions:
            del self.sessions[token]
        return web.json_response({"success": True})

    async def handle_api_check_password(self, request: web.Request) -> web.Response:
        return web.json_response(
            {"success": True, "is_default": self._check_password_default()}
        )

    async def handle_api_config(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token not in self.sessions:
            return web.json_response(
                {"success": False, "message": "未授权"}, status=401
            )

        config_data = {
            "web_port": self._get_config("web_port", 33145),
            "secure_path": self._get_config("secure_path", "chuyeoidc"),
            "enable_group_verify": self._get_web_config("enable_group_verify", True),
            "enable_private_verify": self._get_web_config(
                "enable_private_verify", True
            ),
            "verify_group_id": self._get_web_config("verify_group_id", ""),
            "code_expire_seconds": self._get_web_config("code_expire_seconds", 300),
            "code_length": self._get_web_config("code_length", 6),
            "theme_color": self._get_web_config("theme_color", "#4f46e5"),
            "icon_url": self._get_web_config("icon_url", ""),
            "favicon_url": self._get_web_config("favicon_url", ""),
        }
        return web.json_response({"success": True, "config": config_data})

    async def handle_api_config_save(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token not in self.sessions:
            return web.json_response(
                {"success": False, "message": "未授权"}, status=401
            )

        try:
            data = await request.json()
            logger.info(f"收到保存配置请求: {json.dumps(data, ensure_ascii=False)}")

            allowed_keys = [
                "enable_group_verify",
                "enable_private_verify",
                "verify_group_id",
                "code_expire_seconds",
                "code_length",
                "theme_color",
                "icon_url",
                "favicon_url",
            ]

            update_data = {}
            for key in allowed_keys:
                if key in data:
                    update_data[key] = data[key]

            logger.info(
                f"准备更新的配置: {json.dumps(update_data, ensure_ascii=False)}"
            )

            if self.config_manager.update(update_data):
                logger.info("配置保存成功")
                return web.json_response({"success": True, "message": "配置保存成功"})
            else:
                logger.error("配置保存失败")
                return web.json_response(
                    {"success": False, "message": "配置保存失败"}, status=500
                )
        except Exception as e:
            logger.error(f"保存配置错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_sessions(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token not in self.sessions:
            return web.json_response(
                {"success": False, "message": "未授权"}, status=401
            )

        sessions = []
        for session_id, session in self.oidc_server.sessions.items():
            sessions.append(
                {
                    "session_id": session_id,
                    "code": session.code,
                    "state": session.state,
                    "verified": session.verified,
                    "verified_user_id": session.verified_user_id,
                    "created_at": session.created_at,
                }
            )

        return web.json_response({"success": True, "sessions": sessions})

    async def handle_api_clients(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token not in self.sessions:
            return web.json_response(
                {"success": False, "message": "未授权"}, status=401
            )

        clients = []
        for client_id, client_data in self.client_manager.get_all_clients().items():
            clients.append(
                {
                    "client_id": client_id,
                    "client_secret": client_data.get("client_secret", ""),
                    "name": client_data.get("name", client_id),
                    "home_url": client_data.get("home_url", ""),
                    "redirect_url": client_data.get("redirect_url", ""),
                    "created_at": client_data.get("created_at", 0),
                }
            )

        return web.json_response({"success": True, "clients": clients})

    async def handle_api_clients_add(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token not in self.sessions:
            return web.json_response(
                {"success": False, "message": "未授权"}, status=401
            )

        try:
            data = await request.json()
            client_id = data.get("client_id", "")
            client_secret = data.get("client_secret", "")
            name = data.get("name", "")
            home_url = data.get("home_url", "")
            redirect_url = data.get("redirect_url", "")

            if not client_id:
                client_id = self.client_manager.generate_client_id()
            if not client_secret:
                client_secret = self.client_manager.generate_client_secret()
            if not name:
                name = self.client_manager.generate_client_name()

            if self.client_manager.add_client(
                client_id, client_secret, name, home_url, redirect_url
            ):
                return web.json_response(
                    {
                        "success": True,
                        "message": "客户端创建成功",
                        "client": {
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "name": name,
                            "home_url": home_url,
                            "redirect_url": redirect_url,
                        },
                    }
                )
            else:
                return web.json_response(
                    {"success": False, "message": "客户端已存在"}, status=400
                )
        except Exception as e:
            logger.error(f"添加客户端错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_clients_delete(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token not in self.sessions:
            return web.json_response(
                {"success": False, "message": "未授权"}, status=401
            )

        try:
            data = await request.json()
            client_id = data.get("client_id", "")

            if not client_id:
                return web.json_response(
                    {"success": False, "message": "缺少 client_id"}, status=400
                )

            if self.client_manager.delete_client(client_id):
                return web.json_response({"success": True, "message": "客户端删除成功"})
            else:
                return web.json_response(
                    {"success": False, "message": "客户端不存在"}, status=404
                )
        except Exception as e:
            logger.error(f"删除客户端错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_authorize(self, request: web.Request) -> web.Response:
        redirect_uri = request.query.get("redirect_uri", "")
        response_type = request.query.get("response_type", "code")
        state = request.query.get("state", "")
        client_id = request.query.get("client_id", "")
        scope = request.query.get("scope", "openid profile")

        if response_type != "code":
            return web.json_response({"error": "unsupported_response_type"}, status=400)

        if not redirect_uri:
            return web.json_response(
                {
                    "error": "invalid_request",
                    "error_description": "missing redirect_uri",
                },
                status=400,
            )

        if not client_id:
            return web.json_response(
                {"error": "invalid_request", "error_description": "missing client_id"},
                status=400,
            )

        client = self.client_manager.get_client(client_id)
        if not client:
            return web.json_response(
                {"error": "invalid_client", "error_description": "client_id not found"},
                status=400,
            )

        session_id, verify_code = await self.oidc_server.create_auth_session(
            redirect_uri, state, client_id
        )

        html = self._render_verify_page(
            verify_code, session_id, redirect_uri, state, scope, client
        )
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def handle_token(self, request: web.Request) -> web.Response:
        content_type = request.headers.get("Content-Type", "")
        logger.info(f"Token请求: content_type={content_type}")

        if "application/x-www-form-urlencoded" in content_type:
            data = await request.post()
        else:
            data = await request.json()

        grant_type = data.get("grant_type", "")
        code = data.get("code", "")
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")

        logger.info(
            f"Token参数: grant_type={grant_type}, code={code}, client_id={client_id}"
        )

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            import base64

            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                if ":" in decoded:
                    header_client_id, header_client_secret = decoded.split(":", 1)
                    if not client_id:
                        client_id = header_client_id
                    if not client_secret:
                        client_secret = header_client_secret
            except Exception:
                pass

        if grant_type != "authorization_code":
            return web.json_response({"error": "unsupported_grant_type"}, status=400)

        if not client_id:
            return web.json_response(
                {"error": "invalid_client", "error_description": "missing client_id"},
                status=400,
            )

        if not self.client_manager.verify_client(client_id, client_secret):
            return web.json_response(
                {
                    "error": "invalid_client",
                    "error_description": "client authentication failed",
                },
                status=401,
            )

        token_data = await self.oidc_server.exchange_code(code, client_id)

        if not token_data:
            return web.json_response({"error": "invalid_grant"}, status=400)

        response = web.json_response(token_data)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    async def handle_userinfo(self, request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization", "")
        logger.info(
            f"Userinfo请求: auth_header={auth_header[:30] if auth_header else 'None'}..."
        )

        if not auth_header.startswith("Bearer "):
            logger.warning("Userinfo: 缺少Bearer token")
            return web.json_response({"error": "invalid_token"}, status=401)

        token = auth_header[7:]
        user_data = await self.oidc_server.get_user_info(token)

        logger.info(f"Userinfo数据: {user_data}")

        if not user_data:
            logger.warning("Userinfo: 无效的token")
            return web.json_response({"error": "invalid_token"}, status=401)

        user_info = user_data.get("user_info", {})
        user_id = user_data.get("user_id", "")

        user_name = user_info.get("name", user_id)
        user_name = user_name.replace("\r", "").replace("\n", "").strip()

        userinfo_response = {
            "sub": user_id or user_info.get("id", ""),
            "name": user_name,
            "preferred_username": user_name,
            "nickname": user_name,
            "picture": "",
            "email": f"{user_id}@qq.com" if user_id else "",
            "email_verified": True if user_id else False,
            "locale": "zh-CN",
            "zoneinfo": "Asia/Shanghai",
            "updated_at": int(time.time()),
        }

        logger.info(f"返回userinfo: {userinfo_response}")

        response = web.json_response(userinfo_response)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    async def handle_discovery(self, request: web.Request) -> web.Response:
        host = request.host
        base_url = f"http://{host}"

        discovery = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "userinfo_endpoint": f"{base_url}/userinfo",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["none"],
            "scopes_supported": ["openid", "profile"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": [],
            "claims_supported": ["sub", "name", "id"],
        }

        response = web.json_response(discovery)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    async def handle_verify_page(self, request: web.Request) -> web.Response:
        code = request.query.get("code", "")
        session_id = request.query.get("session_id", "")

        html = self._render_verify_input_page(code, session_id)
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def handle_api_verify(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
            code = data.get("code", "")
            user_id = data.get("user_id", "")

            if not code or not user_id:
                return web.json_response(
                    {"success": False, "message": "参数不完整"}, status=400
                )

            success, result = await self.oidc_server.verify_code_submit(code, user_id)

            if success:
                session = await self.oidc_server.get_session(result)
                if session:
                    redirect_url = f"{session.redirect_uri}?code={session.code}&state={session.state}"
                    return web.json_response(
                        {
                            "success": True,
                            "message": "验证成功",
                            "redirect_url": redirect_url,
                        }
                    )

            return web.json_response({"success": False, "message": result}, status=400)
        except Exception as e:
            logger.error(f"验证处理错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_session_status(self, request: web.Request) -> web.Response:
        try:
            session_id = request.query.get("session_id", "")
            logger.info(f"检查会话状态: session_id={session_id}")
            if not session_id:
                return web.json_response(
                    {"success": False, "message": "缺少session_id"}, status=400
                )

            session = await self.oidc_server.get_session(session_id)
            logger.info(
                f"获取会话结果: session存在={session is not None}, verified={session.verified if session else None}"
            )
            if not session:
                return web.json_response(
                    {"success": False, "message": "会话不存在"}, status=404
                )

            # 添加缓存控制头
            response = web.json_response(
                {
                    "success": True,
                    "verified": session.verified,
                    "verified_user_id": session.verified_user_id,
                }
            )
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response
        except Exception as e:
            logger.error(f"获取会话状态错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    def _render_login_page(
        self, theme_color: str = "#4f46e5", icon_url: str = "", favicon_url: str = ""
    ) -> str:
        icon_html = (
            f'<img src="{icon_url}" class="w-16 h-16 object-cover rounded-lg" style="width: 64px; height: 64px; aspect-ratio: 1/1;" alt="icon">'
            if icon_url
            else """<svg xmlns="http://www.w3.org/2000/svg" style="width: 64px; height: 64px;" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>"""
        )

        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OIDC登录 - 登录</title>
    <link rel="icon" type="image/png" href="{favicon_url}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{
                        primary: '{theme_color}',
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); }}
        .bg-primary {{ background-color: {theme_color}; }}
        .text-primary {{ color: {theme_color}; }}
        .shadow-primary {{ box-shadow: 0 10px 15px -3px {theme_color}33; }}
    </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen flex items-center justify-center p-4 bg-[radial-gradient(circle_at_top_left,_var(--tw-gradient-stops))] from-indigo-100 via-slate-50 to-teal-50">
    <div class="max-w-md w-full">
        <div class="glass rounded-3xl shadow-2xl shadow-primary/30 p-8 md:p-10 border border-white">
            <div class="text-center mb-10">
                <div class="mx-auto mb-6" style="width: 64px; height: 64px;">
                    {icon_html}
                </div>
                <h1 class="text-3xl font-bold text-slate-800 tracking-tight">管理后台</h1>
                <p class="text-slate-500 mt-2">请登录以管理您的 OIDC 服务</p>
            </div>

            <div class="bg-red-50 border border-red-100 text-red-700 px-4 py-3 rounded-xl text-sm mb-8 flex items-start gap-3 hidden" id="defaultWarning">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                </svg>
                <span>您正在使用默认密码，请先在插件管理中修改密码后再登录。</span>
            </div>

            <form id="loginForm" class="space-y-6">
                <div>
                    <label class="block text-sm font-semibold text-slate-700 mb-2 ml-1">用户名</label>
                    <input type="text" id="username" name="username" required 
                        class="w-full px-4 py-3.5 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none placeholder:text-slate-400"
                        placeholder="请输入用户名">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-slate-700 mb-2 ml-1">密码</label>
                    <input type="password" id="password" name="password" required 
                        class="w-full px-4 py-3.5 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none placeholder:text-slate-400"
                        placeholder="请输入密码">
                </div>
                <button type="submit" id="loginBtn"
                    class="w-full py-4 bg-primary hover:opacity-90 text-white rounded-2xl font-bold text-lg shadow-lg shadow-primary/30 transition-all active:scale-[0.98]">
                    登 录
                </button>
            </form>
            <div class="mt-6 text-center text-red-500 text-sm font-medium hidden" id="errorMsg"></div>
        </div>
        <p class="text-center text-slate-400 text-sm mt-8">Powered by <a href="https://github.com/AstrBotDevs/AstrBot" target="_blank" class="text-primary hover:opacity-80">AstrBot</a> & <a href="https://www.chuyel.cn" target="_blank" class="text-primary hover:opacity-80">初叶🍂竹叶-Furry控</a></p>
    </div>

    <script>
        const basePath = window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/')) + '/';
        
        async function checkPasswordStatus() {{
            try {{
                const response = await fetch(basePath + 'api/check_password');
                const data = await response.json();
                if (data.success && data.is_default) {{
                    document.getElementById('defaultWarning').classList.remove('hidden');
                    document.getElementById('loginBtn').disabled = true;
                    document.getElementById('loginBtn').classList.add('opacity-50', 'cursor-not-allowed');
                }}
            }} catch (err) {{
                console.error('检查密码状态失败:', err);
            }}
        }}
        
        checkPasswordStatus();
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorMsg = document.getElementById('errorMsg');
            const btn = e.target.querySelector('button');
            
            btn.disabled = true;
            btn.innerHTML = '<svg class="animate-spin h-5 w-5 mx-auto" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';
            
            try {{
                const response = await fetch(basePath + 'api/login', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ username, password }})
                }});
                const data = await response.json();
                
                if (data.success) {{
                    localStorage.setItem('token', data.token);
                    window.location.href = basePath.substring(0, basePath.length - 1);
                }} else {{
                    errorMsg.textContent = data.message;
                    errorMsg.classList.remove('hidden');
                    btn.disabled = false;
                    btn.textContent = '登 录';
                }}
            }} catch (err) {{
                errorMsg.textContent = '网络错误，请重试';
                errorMsg.classList.remove('hidden');
                btn.disabled = false;
                btn.textContent = '登 录';
            }}
        }});
    </script>
</body>
</html>'''

    def _render_admin_page(
        self,
        is_default_password: bool,
        theme_color: str = "#4f46e5",
        icon_url: str = "",
        favicon_url: str = "",
    ) -> str:
        warning_html = (
            f"""
        <div class="bg-amber-50 border border-amber-100 text-amber-700 px-6 py-4 rounded-2xl flex items-center gap-4 mb-8 shadow-sm">
            <div class="bg-amber-100 p-2 rounded-xl">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
            </div>
            <div class="flex-1 font-medium">您正在使用默认密码，请前往 AstrBot 插件配置页面修改密码！</div>
        </div>
        """
            if is_default_password
            else ""
        )

        icon_html = (
            f'<img src="{icon_url}" class="h-10 w-10 object-cover rounded-lg" alt="icon">'
            if icon_url
            else """<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>"""
        )

        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OIDC登录插件 - 管理后台</title>
    <link rel="icon" type="image/png" href="{favicon_url}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{
                        primary: '{theme_color}',
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(12px); }}
        .tab-active {{ color: {theme_color}; border-bottom: 2px solid {theme_color}; }}
        .custom-scrollbar::-webkit-scrollbar {{ width: 6px; }}
        .custom-scrollbar::-webkit-scrollbar-track {{ background: transparent; }}
        .custom-scrollbar::-webkit-scrollbar-thumb {{ background: #e2e8f0; border-radius: 10px; }}
        .bg-primary {{ background-color: {theme_color}; }}
        .text-primary {{ color: {theme_color}; }}
        .border-primary {{ border-color: {theme_color}; }}
        .shadow-primary {{ box-shadow: 0 10px 15px -3px {theme_color}33; }}
        .hover\:bg-primary:hover {{ background-color: {theme_color}; }}
    </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen bg-[radial-gradient(circle_at_top_right,_var(--tw-gradient-stops))] from-indigo-50 via-slate-50 to-slate-50">
    <nav class="glass sticky top-0 z-50 border-b border-white/50 px-6 py-4">
        <div class="max-w-6xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 flex items-center justify-center">
                    {icon_html}
                </div>
                <div>
                    <h1 class="text-xl font-bold text-slate-800">OIDC 管理后台</h1>
                    <p class="text-xs text-slate-500 font-medium">让支持 OIDC 的程序支持 QQ 登录</p>
                </div>
            </div>
            <button onclick="logout()" class="px-4 py-2 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-xl text-sm font-bold transition-all flex items-center gap-2">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                退出登录
            </button>
        </div>
    </nav>

    <main class="max-w-6xl mx-auto px-6 py-8">
        {warning_html}

        <div class="flex gap-8 mb-8 border-b border-slate-200">
            <button class="tab px-4 py-3 text-sm font-bold text-slate-500 hover:text-primary transition-all tab-active flex items-center gap-2" data-tab="info">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                服务信息
            </button>
            <button class="tab px-4 py-3 text-sm font-bold text-slate-500 hover:text-primary transition-all flex items-center gap-2" data-tab="config">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                配置设置
            </button>
            <button class="tab px-4 py-3 text-sm font-bold text-slate-500 hover:text-primary transition-all flex items-center gap-2" data-tab="sessions">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                </svg>
                认证会话
            </button>
            <button class="tab px-4 py-3 text-sm font-bold text-slate-500 hover:text-primary transition-all flex items-center gap-2" data-tab="clients">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                </svg>
                客户端管理
            </button>
        </div>

        <div id="tab-info" class="tab-content space-y-8">
            <div class="grid md:grid-cols-2 gap-8">
                <div class="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                    <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
                        <span class="w-2 h-6 bg-primary rounded-full"></span>
                        OIDC 端点
                    </h2>
                    <div class="space-y-4">
                        <div class="p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <p class="text-xs font-bold text-slate-400 uppercase mb-1">发现文档</p>
                            <code class="text-sm text-primary break-all" id="discoveryUrl"></code>
                        </div>
                        <div class="p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <p class="text-xs font-bold text-slate-400 uppercase mb-1">授权端点</p>
                            <code class="text-sm text-primary break-all" id="authUrl"></code>
                        </div>
                        <div class="p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <p class="text-xs font-bold text-slate-400 uppercase mb-1">令牌端点</p>
                            <code class="text-sm text-primary break-all" id="tokenUrl"></code>
                        </div>
                        <div class="p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <p class="text-xs font-bold text-slate-400 uppercase mb-1">用户信息</p>
                            <code class="text-sm text-primary break-all" id="userinfoUrl"></code>
                        </div>
                    </div>
                </div>
                <div class="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                    <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
                        <span class="w-2 h-6 bg-teal-500 rounded-full"></span>
                        验证状态
                    </h2>
                    <div class="space-y-4">
                        <div class="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <span class="text-sm font-medium text-slate-600">群聊验证</span>
                            <span class="px-3 py-1 bg-primary/10 text-primary rounded-lg text-xs font-bold" id="groupVerify"></span>
                        </div>
                        <div class="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <span class="text-sm font-medium text-slate-600">私聊验证</span>
                            <span class="px-3 py-1 bg-teal-100 text-teal-600 rounded-lg text-xs font-bold" id="privateVerify"></span>
                        </div>
                        <div class="p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <p class="text-xs font-bold text-slate-400 uppercase mb-1">验证群号</p>
                            <p class="text-sm font-bold text-slate-700" id="verifyGroup"></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="tab-config" class="tab-content hidden space-y-8">
            <div class="grid md:grid-cols-2 gap-8">
                <div class="space-y-8">
                    <div class="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                        <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
                            <span class="w-2 h-6 bg-primary rounded-full"></span>
                            个性化设置
                        </h2>
                        <div class="space-y-6">
                            <div>
                                <label class="block text-sm font-bold text-slate-700 mb-2">主题色</label>
                                <div class="flex items-center gap-4">
                                    <input type="color" id="themeColor" class="w-16 h-12 rounded-xl border border-slate-200 cursor-pointer" value="#4f46e5">
                                    <input type="text" id="themeColorText" class="flex-1 px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="#4f46e5">
                                </div>
                                <p class="text-xs text-slate-500 mt-2">用于后台页面和验证页面的主题色</p>
                            </div>
                            <div>
                                <label class="block text-sm font-bold text-slate-700 mb-2">图标 URL</label>
                                <input type="text" id="iconUrl" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="图标图片URL，留空使用默认图标">
                                <p class="text-xs text-slate-500 mt-2">用于后台页面和验证页面的图标，建议尺寸 64x64</p>
                            </div>
                            <div>
                                <label class="block text-sm font-bold text-slate-700 mb-2">Favicon 图标 URL</label>
                                <input type="text" id="faviconUrl" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="Favicon图标URL，留空使用默认图标">
                                <p class="text-xs text-slate-500 mt-2">用于浏览器标签页图标，建议尺寸 32x32 或 64x64</p>
                            </div>
                        </div>
                    </div>
                    <div class="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                        <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
                            <span class="w-2 h-6 bg-teal-500 rounded-full"></span>
                            验证码设置
                        </h2>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-bold text-slate-700 mb-2">验证码长度</label>
                                <select id="codeLength" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none">
                                    <option value="4">4位</option>
                                    <option value="5">5位</option>
                                    <option value="6">6位</option>
                                    <option value="7">7位</option>
                                    <option value="8">8位</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm font-bold text-slate-700 mb-2">有效期 (秒)</label>
                                <input type="number" id="codeExpire" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" min="60" max="1800">
                            </div>
                        </div>
                    </div>
                </div>
                <div class="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                    <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
                        <span class="w-2 h-6 bg-amber-500 rounded-full"></span>
                        验证方式设置
                    </h2>
                    <div class="space-y-6">
                        <div class="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <div>
                                <p class="text-sm font-bold text-slate-700">启用群聊验证</p>
                                <p class="text-xs text-slate-500">允许在指定群聊中接收验证码</p>
                            </div>
                            <label class="relative inline-flex items-center cursor-pointer">
                                <input type="checkbox" id="enableGroupVerify" class="sr-only peer">
                                <div class="w-11 h-6 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                            </label>
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-700 mb-2">接收验证码的群号</label>
                            <input type="text" id="verifyGroupId" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="多个群号用英文逗号分隔">
                        </div>
                        <div class="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100">
                            <div>
                                <p class="text-sm font-bold text-slate-700">启用私聊验证</p>
                                <p class="text-xs text-slate-500">允许通过私聊机器人发送验证码</p>
                            </div>
                            <label class="relative inline-flex items-center cursor-pointer">
                                <input type="checkbox" id="enablePrivateVerify" class="sr-only peer">
                                <div class="w-11 h-6 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
            <div class="flex justify-end">
                <button onclick="saveConfig()" class="px-8 py-4 bg-primary hover:opacity-90 text-white rounded-2xl font-bold shadow-lg shadow-primary/30 transition-all active:scale-[0.98] flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                    </svg>
                    保存配置
                </button>
            </div>
        </div>

        <div id="tab-sessions" class="tab-content hidden">
            <div class="bg-white rounded-3xl shadow-sm border border-slate-100 overflow-hidden">
                <div class="p-8 border-b border-slate-100 flex items-center justify-between">
                    <h2 class="text-lg font-bold flex items-center gap-2">
                        <span class="w-2 h-6 bg-primary rounded-full"></span>
                        认证会话列表
                    </h2>
                    <span class="px-3 py-1 bg-primary/10 text-primary rounded-lg text-xs font-bold" id="sessionCount">0 个活跃会话</span>
                </div>
                <div class="overflow-x-auto custom-scrollbar">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="bg-slate-50/50">
                                <th class="px-8 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">验证码</th>
                                <th class="px-8 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">状态</th>
                                <th class="px-8 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">验证用户</th>
                                <th class="px-8 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">创建时间</th>
                            </tr>
                        </thead>
                        <tbody id="sessionTable" class="divide-y divide-slate-100">
                            <tr><td colspan="4" class="px-8 py-12 text-center text-slate-400 font-medium">加载中...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="tab-clients" class="tab-content hidden">
            <div class="space-y-8">
                <div class="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                    <div class="flex items-center justify-between mb-6">
                        <h2 class="text-lg font-bold flex items-center gap-2">
                            <span class="w-2 h-6 bg-primary rounded-full"></span>
                            添加新客户端
                        </h2>
                    </div>
                    <div class="grid md:grid-cols-2 gap-6">
                        <div>
                            <label class="block text-sm font-bold text-slate-700 mb-2">客户端名称</label>
                            <input type="text" id="newClientName" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：我的网站">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-700 mb-2">Client ID (留空自动生成)</label>
                            <input type="text" id="newClientId" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="留空自动生成">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-700 mb-2">Client Secret (留空自动生成)</label>
                            <input type="text" id="newClientSecret" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="留空自动生成">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-700 mb-2">主页链接</label>
                            <input type="text" id="newClientHomeUrl" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-slate-700 mb-2">重定向 URL</label>
                            <input type="text" id="newClientRedirectUrl" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com/oauth/callback">
                        </div>
                    </div>
                    <div class="mt-6 flex justify-end">
                        <button onclick="addClient()" class="px-6 py-3 bg-primary hover:opacity-90 text-white rounded-2xl font-bold shadow-lg shadow-primary/30 transition-all active:scale-[0.98] flex items-center gap-2">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                            </svg>
                            添加客户端
                        </button>
                    </div>
                </div>

                <div class="bg-white rounded-3xl shadow-sm border border-slate-100 overflow-hidden">
                    <div class="p-8 border-b border-slate-100 flex items-center justify-between">
                        <h2 class="text-lg font-bold flex items-center gap-2">
                            <span class="w-2 h-6 bg-primary rounded-full"></span>
                            已注册的客户端
                        </h2>
                        <span class="px-3 py-1 bg-primary/10 text-primary rounded-lg text-xs font-bold" id="clientCount">0 个客户端</span>
                    </div>
                    <div class="overflow-x-auto custom-scrollbar">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="bg-slate-50/50">
                                    <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">名称</th>
                                    <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">Client ID</th>
                                    <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">Client Secret</th>
                                    <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">主页链接</th>
                                    <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">重定向 URL</th>
                                    <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">创建时间</th>
                                    <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">操作</th>
                                </tr>
                            </thead>
                            <tbody id="clientTable" class="divide-y divide-slate-100">
                                <tr><td colspan="7" class="px-6 py-12 text-center text-slate-400 font-medium">暂无客户端，请添加新客户端</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <footer class="border-t border-slate-200 mt-12 py-6 text-center">
        <p class="text-sm text-slate-500">
            Powered by <a href="https://github.com/AstrBotDevs/AstrBot" target="_blank" class="text-primary hover:opacity-80 font-medium">AstrBot</a> & <a href="https://www.chuyel.cn" target="_blank" class="text-primary hover:opacity-80 font-medium">初叶🍂竹叶-Furry控</a>
        </p>
    </footer>

    <div id="toast" class="fixed bottom-8 right-8 px-6 py-4 rounded-2xl shadow-2xl transform translate-y-20 opacity-0 transition-all duration-300 z-[100] flex items-center gap-3 font-bold text-white"></div>

    <script>
        const token = localStorage.getItem('token');
        const basePath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
        if (!token) {{ window.location.href = basePath + 'login'; }}
        
        document.querySelectorAll('.tab').forEach(tab => {{
            tab.addEventListener('click', () => {{
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
                tab.classList.add('tab-active');
                document.getElementById('tab-' + tab.dataset.tab).classList.remove('hidden');
            }});
        }});
        
        function showToast(message, type) {{
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = `fixed bottom-8 right-8 px-6 py-4 rounded-2xl shadow-2xl z-[100] flex items-center gap-3 font-bold text-white transition-all duration-300 ${{type === 'success' ? 'bg-teal-500 shadow-teal-200' : 'bg-rose-500 shadow-rose-200'}}`;
            toast.style.transform = 'translateY(0)';
            toast.style.opacity = '1';
            setTimeout(() => {{
                toast.style.transform = 'translateY(20px)';
                toast.style.opacity = '0';
            }}, 3000);
        }}
        
        async function loadConfig() {{
            try {{
                const response = await fetch(basePath + 'api/config', {{
                    headers: {{ 'Authorization': 'Bearer ' + token }}
                }});
                const data = await response.json();
                if (!data.success) {{ window.location.href = basePath + 'login'; return; }}
                
                const config = data.config;
                const baseUrl = window.location.origin;
                
                document.getElementById('discoveryUrl').textContent = baseUrl + '/.well-known/openid-configuration';
                document.getElementById('authUrl').textContent = baseUrl + '/authorize';
                document.getElementById('tokenUrl').textContent = baseUrl + '/token';
                document.getElementById('userinfoUrl').textContent = baseUrl + '/userinfo';
                document.getElementById('groupVerify').textContent = config.enable_group_verify ? '已启用' : '已禁用';
                document.getElementById('privateVerify').textContent = config.enable_private_verify ? '已启用' : '已禁用';
                document.getElementById('verifyGroup').textContent = config.verify_group_id || '未配置';
                
                document.getElementById('codeLength').value = config.code_length || 6;
                document.getElementById('codeExpire').value = config.code_expire_seconds || 300;
                document.getElementById('enableGroupVerify').checked = config.enable_group_verify !== false;
                document.getElementById('enablePrivateVerify').checked = config.enable_private_verify !== false;
                document.getElementById('verifyGroupId').value = config.verify_group_id || '';
                
                const themeColor = config.theme_color || '#4f46e5';
                document.getElementById('themeColor').value = themeColor;
                document.getElementById('themeColorText').value = themeColor;
                document.getElementById('iconUrl').value = config.icon_url || '';
                document.getElementById('faviconUrl').value = config.favicon_url || '';
                
                // 更新Favicon
                if (config.favicon_url) {{
                    let favicon = document.querySelector('link[rel="icon"]');
                    if (!favicon) {{
                        favicon = document.createElement('link');
                        favicon.rel = 'icon';
                        favicon.type = 'image/png';
                        document.head.appendChild(favicon);
                    }}
                    favicon.href = config.favicon_url;
                }}
            }} catch (err) {{
                console.error('加载配置失败:', err);
            }}
        }}
        
        async function saveConfig() {{
            const config = {{
                code_length: parseInt(document.getElementById('codeLength').value),
                code_expire_seconds: parseInt(document.getElementById('codeExpire').value),
                enable_group_verify: document.getElementById('enableGroupVerify').checked,
                enable_private_verify: document.getElementById('enablePrivateVerify').checked,
                verify_group_id: document.getElementById('verifyGroupId').value,
                theme_color: document.getElementById('themeColor').value,
                icon_url: document.getElementById('iconUrl').value,
                favicon_url: document.getElementById('faviconUrl').value
            }};
            
            try {{
                const response = await fetch(basePath + 'api/config/save', {{
                    method: 'POST',
                    headers: {{ 
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    }},
                    body: JSON.stringify(config)
                }});
                const data = await response.json();
                
                if (data.success) {{
                    showToast('配置保存成功！页面将刷新以应用新的主题色和图标设置。', 'success');
                    document.getElementById('groupVerify').textContent = config.enable_group_verify ? '已启用' : '已禁用';
                    document.getElementById('privateVerify').textContent = config.enable_private_verify ? '已启用' : '已禁用';
                    document.getElementById('verifyGroup').textContent = config.verify_group_id || '未配置';
                    setTimeout(() => location.reload(), 1500);
                }} else {{
                    showToast(data.message || '保存失败', 'error');
                }}
            }} catch (err) {{
                console.error('保存配置失败:', err);
                showToast('网络错误，请重试', 'error');
            }}
        }}
        
        async function loadSessions() {{
            try {{
                const response = await fetch(basePath + 'api/sessions', {{
                    headers: {{ 'Authorization': 'Bearer ' + token }}
                }});
                const data = await response.json();
                if (!data.success) return;
                
                document.getElementById('sessionCount').textContent = `${{data.sessions.length}} 个活跃会话`;
                const tbody = document.getElementById('sessionTable');
                if (data.sessions.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="4" class="px-8 py-12 text-center text-slate-400 font-medium">暂无认证会话</td></tr>';
                    return;
                }}
                
                tbody.innerHTML = data.sessions.map(s => `
                    <tr class="hover:bg-slate-50/50 transition-colors">
                        <td class="px-8 py-4"><code class="bg-primary/10 text-primary px-2 py-1 rounded-lg font-bold text-sm">${{s.code}}</code></td>
                        <td class="px-8 py-4">
                            <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold ${{s.verified ? 'bg-teal-100 text-teal-600' : 'bg-amber-100 text-amber-600'}}">
                                <span class="w-1.5 h-1.5 rounded-full ${{s.verified ? 'bg-teal-500' : 'bg-amber-500'}}"></span>
                                ${{s.verified ? '已验证' : '待验证'}}
                            </span>
                        </td>
                        <td class="px-8 py-4 text-sm font-medium text-slate-600">${{s.verified_user_id || '<span class="text-slate-300">-</span>'}}</td>
                        <td class="px-8 py-4 text-sm text-slate-400 font-medium">${{new Date(s.created_at * 1000).toLocaleString()}}</td>
                    </tr>
                `).join('');
            }} catch (err) {{
                console.error('加载会话失败:', err);
            }}
        }}
        
        async function loadClients() {{
            try {{
                const response = await fetch(basePath + 'api/clients', {{
                    headers: {{ 'Authorization': 'Bearer ' + token }}
                }});
                const data = await response.json();
                if (!data.success) return;
                
                document.getElementById('clientCount').textContent = `${{data.clients.length}} 个客户端`;
                const tbody = document.getElementById('clientTable');
                if (data.clients.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="7" class="px-6 py-12 text-center text-slate-400 font-medium">暂无客户端，请添加新客户端</td></tr>';
                    return;
                }}
                
                function truncateUrl(url, maxLen = 20) {{
                    if (!url) return '<span class="text-slate-300">-</span>';
                    if (url.length <= maxLen) return url;
                    return url.substring(0, maxLen) + '...';
                }}
                
                tbody.innerHTML = data.clients.map(c => `
                    <tr class="hover:bg-slate-50/50 transition-colors">
                        <td class="px-6 py-4 text-sm font-bold text-slate-700">
                            <div class="flex items-center gap-2">
                                ${{c.name}}
                                <button onclick="copyText('${{c.name}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <div class="flex items-center gap-2">
                                <code class="bg-indigo-50 text-indigo-600 px-2 py-1 rounded-lg font-bold text-sm">${{c.client_id}}</code>
                                <button onclick="copyText('${{c.client_id}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <div class="flex items-center gap-2">
                                <code class="bg-emerald-50 text-emerald-600 px-2 py-1 rounded-lg font-bold text-sm max-w-[80px] truncate" title="${{c.client_secret}}">${{c.client_secret}}</code>
                                <button onclick="copyText('${{c.client_secret}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>
                        </td>
                        <td class="px-6 py-4 text-sm text-slate-600">
                            <div class="flex items-center gap-2">
                                <span title="${{c.home_url || ''}}">${{truncateUrl(c.home_url)}}</span>
                                ${{c.home_url ? `<button onclick="copyText('${{c.home_url}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制"><svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg></button>` : ''}}
                            </div>
                        </td>
                        <td class="px-6 py-4 text-sm text-slate-600">
                            <div class="flex items-center gap-2">
                                <span title="${{c.redirect_url || ''}}">${{truncateUrl(c.redirect_url)}}</span>
                                ${{c.redirect_url ? `<button onclick="copyText('${{c.redirect_url}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制"><svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg></button>` : ''}}
                            </div>
                        </td>
                        <td class="px-6 py-4 text-sm text-slate-400 font-medium">${{new Date(c.created_at * 1000).toLocaleString()}}</td>
                        <td class="px-6 py-4">
                            <button onclick="deleteClient('${{c.client_id}}')" class="px-3 py-1.5 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-lg text-xs font-bold transition-all">删除</button>
                        </td>
                    </tr>
                `).join('');
            }} catch (err) {{
                console.error('加载客户端失败:', err);
            }}
        }}
        
        function copyText(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                showToast('已复制到剪贴板', 'success');
            }}).catch(err => {{
                console.error('复制失败:', err);
            }});
        }}
        
        async function addClient() {{
            const name = document.getElementById('newClientName').value;
            const client_id = document.getElementById('newClientId').value;
            const client_secret = document.getElementById('newClientSecret').value;
            const home_url = document.getElementById('newClientHomeUrl').value;
            const redirect_url = document.getElementById('newClientRedirectUrl').value;
            
            try {{
                const response = await fetch(basePath + 'api/clients/add', {{
                    method: 'POST',
                    headers: {{ 
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    }},
                    body: JSON.stringify({{
                        name: name,
                        client_id: client_id,
                        client_secret: client_secret,
                        home_url: home_url,
                        redirect_url: redirect_url
                    }})
                }});
                const data = await response.json();
                
                if (data.success) {{
                    showToast(`客户端创建成功！\\nClient ID: ${{data.client.client_id}}\\nClient Secret: ${{data.client.client_secret}}`, 'success');
                    document.getElementById('newClientName').value = '';
                    document.getElementById('newClientId').value = '';
                    document.getElementById('newClientSecret').value = '';
                    document.getElementById('newClientHomeUrl').value = '';
                    document.getElementById('newClientRedirectUrl').value = '';
                    loadClients();
                }} else {{
                    showToast(data.message || '添加失败', 'error');
                }}
            }} catch (err) {{
                console.error('添加客户端失败:', err);
                showToast('网络错误，请重试', 'error');
            }}
        }}
        
        async function deleteClient(clientId) {{
            if (!confirm(`确定要删除客户端 "${{clientId}}" 吗？`)) return;
            
            try {{
                const response = await fetch(basePath + 'api/clients/delete', {{
                    method: 'POST',
                    headers: {{ 
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    }},
                    body: JSON.stringify({{ client_id: clientId }})
                }});
                const data = await response.json();
                
                if (data.success) {{
                    showToast('客户端删除成功！', 'success');
                    loadClients();
                }} else {{
                    showToast(data.message || '删除失败', 'error');
                }}
            }} catch (err) {{
                console.error('删除客户端失败:', err);
                showToast('网络错误，请重试', 'error');
            }}
        }}
        
        async function logout() {{
            await fetch(basePath + 'api/logout', {{
                method: 'POST',
                headers: {{ 'Authorization': 'Bearer ' + token }}
            }});
            localStorage.removeItem('token');
            window.location.href = basePath + 'login';
        }}
        
        document.getElementById('themeColor').addEventListener('input', function(e) {{
            document.getElementById('themeColorText').value = e.target.value;
        }});
        
        document.getElementById('themeColorText').addEventListener('input', function(e) {{
            const color = e.target.value;
            if (/^#[0-9A-Fa-f]{{6}}$/.test(color)) {{
                document.getElementById('themeColor').value = color;
            }}
        }});
        
        loadConfig();
        loadSessions();
        loadClients();
        setInterval(loadSessions, 5000);
    </script>
</body>
</html>'''

    def _render_verify_page(
        self,
        code: str,
        session_id: str,
        redirect_uri: str,
        state: str,
        scope: str = "openid profile",
        client: dict = None,
    ) -> str:
        verify_group_id = self._get_web_config("verify_group_id", "")
        enable_group_verify = self._get_web_config("enable_group_verify", True)
        enable_private_verify = self._get_web_config("enable_private_verify", True)
        theme_color = self._get_web_config("theme_color", "#4f46e5")
        icon_url = self._get_web_config(
            "icon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        favicon_url = self._get_web_config(
            "favicon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )

        client_name = client.get("name", "未知应用") if client else "未知应用"

        icon_html = (
            f'<img src="{icon_url}" class="h-16 w-16 object-cover rounded-lg" alt="icon">'
            if icon_url
            else """<svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>"""
        )

        scope_descriptions = {
            "openid": {
                "name": "openid",
                "desc": "识别你的账号主体（sub），用于登录鉴权。",
            },
            "profile": {
                "name": "profile",
                "desc": "读取昵称、头像等基础资料，用于展示个人信息。",
            },
            "email": {
                "name": "email",
                "desc": "读取邮箱标识信息（当前映射为 QQ 邮箱形式）。",
            },
        }

        scopes = scope.split()
        scope_items = ""
        for s in scopes:
            if s in scope_descriptions:
                scope_items += f"""
                <div class="flex items-start gap-3 p-3 bg-slate-50 rounded-xl">
                    <div class="bg-primary/10 p-1.5 rounded-lg">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <div>
                        <p class="text-sm font-bold text-slate-700">{scope_descriptions[s]["name"]}</p>
                        <p class="text-xs text-slate-500 mt-0.5">{scope_descriptions[s]["desc"]}</p>
                    </div>
                </div>"""

        group_info = ""
        if enable_group_verify and verify_group_id:
            groups = [g.strip() for g in verify_group_id.split(",") if g.strip()]
            if groups:
                group_info = f"""
                <div class="flex items-start gap-3 p-4 bg-primary/5 rounded-2xl border border-primary/10">
                    <div class="bg-primary p-1.5 rounded-lg text-white">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                        </svg>
                    </div>
                    <div>
                        <p class="text-xs font-bold text-primary uppercase tracking-wider mb-1">发送到群聊</p>
                        <p class="text-sm font-medium text-slate-700">{", ".join(groups)}</p>
                    </div>
                </div>"""

        private_info = ""
        if enable_private_verify:
            private_info = f"""
            <div class="flex items-start gap-3 p-4 bg-teal-50 rounded-2xl border border-teal-100">
                <div class="bg-teal-500 p-1.5 rounded-lg text-white">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                    </svg>
                </div>
                <div>
                    <p class="text-xs font-bold text-teal-600 uppercase tracking-wider mb-1">私聊验证</p>
                    <p class="text-sm font-medium text-slate-700">直接私聊机器人发送验证码</p>
                </div>
            </div>"""

        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OIDC 验证 - 身份验证</title>
    <link rel="icon" type="image/png" href="{favicon_url}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{
                        primary: '{theme_color}',
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); }}
        .code-char {{ display: inline-block; width: 3rem; height: 4rem; line-height: 4rem; background: white; border-radius: 1rem; margin: 0 0.25rem; font-size: 2rem; font-weight: 800; color: {theme_color}; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
        .bg-primary {{ background-color: {theme_color}; }}
        .text-primary {{ color: {theme_color}; }}
        .border-primary {{ border-color: {theme_color}; }}
        .shadow-primary {{ box-shadow: 0 10px 15px -3px {theme_color}33; }}
        /* 桌面端左右布局 - 合并为一个框 */
        @media (min-width: 1024px) {{
            .desktop-container {{
                max-width: 800px;
                width: 100%;
            }}
            .desktop-inner {{
                display: grid;
                grid-template-columns: 50% 50%;
                gap: 0;
            }}
            .desktop-left, .desktop-right {{
                width: 100%;
                box-sizing: border-box;
            }}
            .mobile-only {{
                display: none !important;
            }}
        }}
        /* 移动端单列布局 */
        @media (max-width: 1023px) {{
            .desktop-container {{
                max-width: 28rem;
                width: 100%;
            }}
            .desktop-left {{
                display: none;
            }}
        }}
    </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen flex items-center justify-center p-4 bg-[radial-gradient(circle_at_bottom_right,_var(--tw-gradient-stops))] from-indigo-100 via-slate-50 to-teal-50">
    <div class="desktop-container mx-auto">
        <div class="glass rounded-[2.5rem] shadow-2xl shadow-primary/30 p-6 sm:p-8 md:p-10 border border-white">
            <!-- 桌面端左右布局 -->
            <div class="desktop-inner">
                <!-- 桌面端左侧：应用信息和权限 -->
                <div class="desktop-left text-left p-6" style="padding-right: 2rem;">
                    <div class="flex items-center gap-4 mb-8">
                        <div style="width: 64px; height: 64px; flex-shrink: 0;">
                            {icon_html}
                        </div>
                        <div>
                            <h1 class="text-2xl font-bold text-slate-800 tracking-tight">授权登录</h1>
                            <p class="text-slate-500 mt-1 font-medium text-sm"><strong class="text-primary">{client_name}</strong> 请求访问你的账号</p>
                        </div>
                    </div>
                    
                    <div>
                        <p class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">请求的权限</p>
                        <div class="space-y-2">
                            {scope_items}
                        </div>
                    </div>
                </div>
                
                <!-- 右侧：验证码和操作 -->
                <div class="desktop-right text-center" style="padding-left: 2rem;">
                    <!-- 移动端显示的应用信息 -->
                    <div class="mobile-only mb-6">
                        <div class="mx-auto mb-6" style="width: 64px; height: 64px;">
                            {icon_html}
                        </div>
                        <h1 class="text-2xl font-bold text-slate-800 tracking-tight">授权登录</h1>
                        <p class="text-slate-500 mt-1 font-medium text-sm"><strong class="text-primary">{client_name}</strong> 请求访问你的账号</p>
                    </div>

                    <div class="bg-primary rounded-3xl p-6 mb-6 shadow-xl shadow-primary/30 relative overflow-hidden">
                        <div class="absolute top-0 left-0 w-full h-full opacity-10 pointer-events-none">
                            <svg width="100%" height="100%" viewBox="0 0 100 100" preserveAspectRatio="none">
                                <path d="M0 100 C 20 0 50 0 100 100 Z" fill="white"></path>
                            </svg>
                        </div>
                        <p class="text-white/70 text-xs font-bold uppercase tracking-[0.2em] mb-3 relative z-10">验证码</p>
                        <div class="flex justify-center relative z-10">
                            {" ".join([f'<span class="code-char">{char}</span>' for char in code])}
                        </div>
                    </div>

                    <!-- 验证码下方的验证方式说明 -->
                    <div class="space-y-3 mb-6 text-left">
                        {group_info}
                        {private_info}
                    </div>

                    <!-- 移动端显示的权限 -->
                    <div class="mobile-only">
                        <div class="mb-6 text-left">
                            <p class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">请求的权限</p>
                            <div class="space-y-2">
                                {scope_items}
                            </div>
                        </div>
                    </div>

                    <div id="status" class="hidden flex items-center justify-center gap-3 py-4 px-6 bg-slate-50 rounded-2xl border border-slate-100 mb-4">
                        <div class="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
                        <span class="text-sm font-bold text-slate-500">等待验证中...</span>
                    </div>
                    
                    <div id="successStatus" class="hidden flex items-center justify-center gap-3 py-4 px-6 bg-teal-50 rounded-2xl border border-teal-100 mb-4">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-teal-600" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                        </svg>
                        <span class="text-sm font-bold text-teal-600">验证成功！</span>
                    </div>
                    
                    <button id="confirmBtn" onclick="checkAndRedirect()" class="w-full py-3.5 bg-primary hover:opacity-90 text-white font-bold rounded-2xl shadow-lg shadow-primary/30 transition-all transform hover:scale-[1.02] active:scale-[0.98]">
                        完成并继续
                    </button>
                    
                    <div class="mt-6 text-rose-500 text-sm font-medium hidden" id="errorMsg"></div>
                </div>
            </div>
        </div>
        <p class="text-center text-slate-400 text-sm mt-8">Powered by <a href="https://github.com/AstrBotDevs/AstrBot" target="_blank" class="text-primary hover:opacity-80">AstrBot</a> & <a href="https://www.chuyel.cn" target="_blank" class="text-primary hover:opacity-80">初叶🍂竹叶-Furry控</a></p>
    </div>

    <script>
        var sessionId = '{session_id}';
        var code = '{code}';
        var isVerified = false;
        var redirected = false;
        var lastClickTime = 0;
        var CLICK_INTERVAL = 2000;
        var checkIntervalId = null;
        var lastPollTime = 0;
        var POLL_INTERVAL_MS = 1000;
        
        function doRedirect() {{
            if (redirected) return;
            redirected = true;
            window.location.href = '{redirect_uri}?code={code}&state={state}';
        }}
        
        function updateUIForVerified() {{
            if (isVerified) return;
            isVerified = true;
            
            var statusEl = document.getElementById('status');
            var successStatusEl = document.getElementById('successStatus');
            var confirmBtn = document.getElementById('confirmBtn');
            var errorMsg = document.getElementById('errorMsg');
            
            if (statusEl) statusEl.classList.add('hidden');
            if (successStatusEl) successStatusEl.classList.remove('hidden');
            if (confirmBtn) {{
                confirmBtn.textContent = '验证成功，点击继续';
                confirmBtn.classList.add('bg-teal-500');
                confirmBtn.classList.remove('bg-primary');
                confirmBtn.disabled = false;
            }}
            if (errorMsg) errorMsg.classList.add('hidden');
        }}
        
        function checkAndRedirect() {{
            var now = Date.now();
            var errorMsg = document.getElementById('errorMsg');
            
            // 如果已经验证过了，直接跳转
            if (isVerified) {{
                doRedirect();
                return;
            }}
            
            // 检查是否在2秒冷却期内
            if (now - lastClickTime < CLICK_INTERVAL) {{
                errorMsg.textContent = '请稍后再试（每2秒可请求一次）';
                errorMsg.classList.remove('hidden');
                return;
            }}
            
            lastClickTime = now;
            errorMsg.classList.add('hidden');
            
            // 显示加载状态
            var btn = document.getElementById('confirmBtn');
            var originalText = btn.textContent;
            btn.textContent = '检查中...';
            btn.disabled = true;
            
            // 使用 XMLHttpRequest 发送请求
            var xhr = new XMLHttpRequest();
            var url = '../api/session/status?session_id=' + sessionId + '&_t=' + Date.now();
            xhr.open('GET', url, true);
            xhr.setRequestHeader('Cache-Control', 'no-cache');
            xhr.onreadystatechange = function() {{
                if (xhr.readyState === 4) {{
                    if (xhr.status === 200) {{
                        try {{
                            var data = JSON.parse(xhr.responseText);
                            if (data.success === true && data.verified === true) {{
                                updateUIForVerified();
                                // 延迟一下再跳转，让用户看到验证成功的状态
                                setTimeout(doRedirect, 800);
                            }} else {{
                                errorMsg.textContent = '尚未完成验证，请在QQ中发送验证码';
                                errorMsg.classList.remove('hidden');
                                btn.textContent = originalText;
                                btn.disabled = false;
                            }}
                        }} catch (e) {{
                            errorMsg.textContent = '解析响应失败';
                            errorMsg.classList.remove('hidden');
                            btn.textContent = originalText;
                            btn.disabled = false;
                        }}
                    }} else {{
                        errorMsg.textContent = '网络错误，请重试';
                        errorMsg.classList.remove('hidden');
                        btn.textContent = originalText;
                        btn.disabled = false;
                    }}
                }}
            }};
            xhr.send();
        }}
        
        function checkStatus() {{
            if (isVerified) return;
            
            var xhr = new XMLHttpRequest();
            // 添加时间戳防止缓存
            var url = '../api/session/status?session_id=' + sessionId + '&_t=' + Date.now();
            xhr.open('GET', url, true);
            xhr.setRequestHeader('Cache-Control', 'no-cache');
            xhr.onreadystatechange = function() {{
                if (xhr.readyState === 4 && xhr.status === 200) {{
                    try {{
                        var data = JSON.parse(xhr.responseText);
                        if (data.success === true && data.verified === true && !isVerified) {{
                            updateUIForVerified();
                            // 验证成功后停止轮询
                            if (checkIntervalId) {{
                                clearInterval(checkIntervalId);
                                checkIntervalId = null;
                            }}
                        }}
                    }} catch (e) {{}}
                }}
            }};
            xhr.send();
        }}
        
        // 使用 requestAnimationFrame 保持活跃
        function scheduleCheck(timestamp) {{
            if (isVerified) return;
            
            // 如果距离上次检查超过间隔时间，执行检查
            if (timestamp - lastPollTime >= POLL_INTERVAL_MS) {{
                lastPollTime = timestamp;
                checkStatus();
            }}
            
            requestAnimationFrame(scheduleCheck);
        }}
        
        // 页面可见性变化时立即检查（多次）
        document.addEventListener('visibilitychange', function() {{
            if (!document.hidden && !isVerified) {{
                lastPollTime = 0;
                // 立即检查，然后每隔100ms检查一次，共检查10次
                checkStatus();
                for (var i = 1; i <= 10; i++) {{
                    setTimeout(function() {{
                        if (!isVerified) checkStatus();
                    }}, i * 100);
                }}
            }}
        }});
        
        // 窗口获得焦点时立即检查（多次）
        window.addEventListener('focus', function() {{
            if (!isVerified) {{
                lastPollTime = 0;
                checkStatus();
                for (var i = 1; i <= 10; i++) {{
                    setTimeout(function() {{
                        if (!isVerified) checkStatus();
                    }}, i * 100);
                }}
            }}
        }});
        
        // 点击页面任意位置时检查
        document.addEventListener('click', function() {{
            if (!isVerified) {{
                checkStatus();
            }}
        }});
        
        // 鼠标移动时检查（节流）
        var lastMouseMoveCheck = 0;
        document.addEventListener('mousemove', function() {{
            var now = Date.now();
            if (!isVerified && now - lastMouseMoveCheck > 500) {{
                lastMouseMoveCheck = now;
                checkStatus();
            }}
        }});
        
        // 页面加载后立即开始
        checkStatus();
        requestAnimationFrame(scheduleCheck);
        checkIntervalId = setInterval(checkStatus, 1000);
    </script>
</body>
</html>'''

    def _render_verify_input_page(self, code: str, session_id: str) -> str:
        theme_color = self._get_web_config("theme_color", "#4f46e5")
        icon_url = self._get_web_config(
            "icon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        favicon_url = self._get_web_config(
            "favicon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )

        icon_html = (
            f'<img src="{icon_url}" class="h-16 w-16 object-cover rounded-lg" alt="icon">'
            if icon_url
            else """<svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>"""
        )

        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OIDC 验证 - 输入验证码</title>
    <link rel="icon" type="image/png" href="{favicon_url}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{
                        primary: '{theme_color}',
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); }}
        .bg-primary {{ background-color: {theme_color}; }}
        .text-primary {{ color: {theme_color}; }}
        .shadow-primary {{ box-shadow: 0 10px 15px -3px {theme_color}33; }}
    </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen flex items-center justify-center p-4 bg-[radial-gradient(circle_at_top_left,_var(--tw-gradient-stops))] from-indigo-100 via-slate-50 to-teal-50">
    <div class="max-w-md w-full">
        <div class="glass rounded-[2.5rem] shadow-2xl shadow-primary/30 p-8 md:p-10 border border-white">
            <div class="text-center mb-10">
                <div class="inline-flex items-center justify-center w-16 h-16 mb-6">
                    {icon_html}
                </div>
                <h1 class="text-3xl font-bold text-slate-800 tracking-tight">手动验证</h1>
                <p class="text-slate-500 mt-2 font-medium">请输入验证码和您的用户 ID</p>
            </div>

            <form id="verifyForm" class="space-y-6">
                <div>
                    <label class="block text-sm font-semibold text-slate-700 mb-2 ml-1">验证码</label>
                    <input type="text" id="code" name="code" value="{code}" required 
                        class="w-full px-4 py-3.5 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none placeholder:text-slate-400 font-mono text-lg tracking-wider"
                        placeholder="请输入验证码">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-slate-700 mb-2 ml-1">用户 ID</label>
                    <input type="text" id="userId" name="userId" required 
                        class="w-full px-4 py-3.5 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none placeholder:text-slate-400"
                        placeholder="请输入您的 QQ 号或用户 ID">
                </div>
                <button type="submit" 
                    class="w-full py-4 bg-primary hover:opacity-90 text-white rounded-2xl font-bold text-lg shadow-lg shadow-primary/30 transition-all active:scale-[0.98] flex items-center justify-center gap-2">
                    <span>立即验证</span>
                </button>
            </form>
            
            <div id="message" class="mt-6 text-center p-4 rounded-2xl text-sm font-bold hidden"></div>
        </div>
        <p class="text-center text-slate-400 text-sm mt-8">Powered by <a href="https://github.com/AstrBotDevs/AstrBot" target="_blank" class="text-primary hover:opacity-80">AstrBot</a> & <a href="https://www.chuyel.cn" target="_blank" class="text-primary hover:opacity-80">初叶🍂竹叶-Furry控</a></p>
    </div>

    <script>
        document.getElementById('verifyForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const code = document.getElementById('code').value;
            const userId = document.getElementById('userId').value;
            const message = document.getElementById('message');
            const btn = e.target.querySelector('button');
            
            btn.disabled = true;
            const originalBtnContent = btn.innerHTML;
            btn.innerHTML = '<svg class="animate-spin h-5 w-5 text-white" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';
            
            try {{
                const response = await fetch('../api/verify', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ code, user_id: userId }})
                }});
                const data = await response.json();
                
                message.classList.remove('hidden', 'bg-teal-50', 'text-teal-600', 'bg-rose-50', 'text-rose-600');
                
                if (data.success) {{
                    message.classList.add('bg-teal-50', 'text-teal-600');
                    message.textContent = '验证成功！正在跳转...';
                    if (data.redirect_url) {{
                        setTimeout(() => {{ window.location.href = data.redirect_url; }}, 1500);
                    }}
                }} else {{
                    message.classList.add('bg-rose-50', 'text-rose-600');
                    message.textContent = data.message || '验证失败';
                    btn.disabled = false;
                    btn.innerHTML = originalBtnContent;
                }}
            }} catch (err) {{
                message.classList.remove('hidden');
                message.classList.add('bg-rose-50', 'text-rose-600');
                message.textContent = '网络错误，请重试';
                btn.disabled = false;
                btn.innerHTML = originalBtnContent;
            }}
        }});
    </script>
</body>
</html>'''


@register("astrbot_plugin_chuyeoidc", "chuyegzs", "OIDC登录插件", "1.0.2")
class ChuyeOIDCPlugin(Star):
    """OIDC 登录插件主类

    AstrBot 插件入口类，负责：
    - 插件初始化和配置加载
    - Web 服务启动
    - QQ 消息处理（验证码验证）
    - 插件生命周期管理
    """

    def __init__(self, context: Context, config=None):
        super().__init__(context)
        self.config = config
        self.config_manager: Optional[ConfigManager] = None
        self.client_manager: Optional[ClientManager] = None
        self.oidc_server: Optional[OIDCServer] = None
        self.web_handler: Optional[WebHandler] = None
        self._cleanup_task: Optional[asyncio.Task] = None

    def _get_config(self, key: str, default=None):
        if not self.config:
            return default
        return self.config.get(key, default)

    def _get_web_config(self, key: str, default=None):
        """获取Web配置"""
        if hasattr(self, "config_manager") and self.config_manager:
            return self.config_manager.get(key, default)
        return default

    async def initialize(self):
        logger.info("OIDC登录插件正在初始化...")

        self.config_manager = ConfigManager(self)
        self.client_manager = ClientManager()
        self.oidc_server = OIDCServer(self, self.config_manager, self.client_manager)
        self.web_handler = WebHandler(
            self, self.oidc_server, self.config_manager, self.client_manager
        )

        port = self._get_config("web_port", 33145)
        secure_path = self._get_config("secure_path", "chuyeoidc")

        if not secure_path:
            logger.error("安全入口路径不能为空")
            secure_path = "chuyeoidc"

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.web_handler.handle_root)

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()

        self.oidc_server.app = app
        self.oidc_server.runner = runner
        self.oidc_server.site = site

        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

        logger.info(f"OIDC登录插件初始化完成，服务端口: {port}")
        logger.info(f"管理后台地址: http://localhost:{port}/{secure_path}")
        logger.info(
            f"OIDC发现文档: http://localhost:{port}/.well-known/openid-configuration"
        )

    async def terminate(self):
        logger.info("OIDC登录插件正在停止...")

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        if self.oidc_server and self.oidc_server.site:
            await self.oidc_server.site.stop()
        if self.oidc_server and self.oidc_server.runner:
            await self.oidc_server.runner.cleanup()

        logger.info("OIDC登录插件已停止")

    async def _periodic_cleanup(self):
        while True:
            try:
                await asyncio.sleep(60)
                if self.oidc_server:
                    await self.oidc_server.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"定期清理时发生错误: {e}")

    @filter.command("验证码")
    async def verify_code(self, event: AstrMessageEvent):
        message_str = event.get_message_str().strip()
        code = message_str.replace("验证码", "").strip()

        logger.info(f"收到验证码命令: {code}")

        if not code:
            yield event.plain_result("请输入验证码，例如：验证码 123456")
            return

        if not self.oidc_server:
            yield event.plain_result("服务未初始化")
            return

        # 检查群聊限制
        message_type = event.get_message_type()
        is_group = (
            message_type.value == "GroupMessage" or message_type.name == "GROUP_MESSAGE"
        )
        group_id = event.get_group_id() if is_group else ""
        enable_group_verify = self._get_web_config("enable_group_verify", True)
        enable_private_verify = self._get_web_config("enable_private_verify", True)
        verify_group_id = self._get_web_config("verify_group_id", "")

        logger.info(
            f"消息类型: {message_type}, is_group: {is_group}, group_id: {group_id}"
        )
        logger.info(
            f"群聊验证启用: {enable_group_verify}, 私聊验证启用: {enable_private_verify}, 允许的群: {verify_group_id}"
        )

        if is_group:
            # 群聊消息
            if not enable_group_verify:
                logger.info("群聊验证未启用，跳过")
                return
            # 检查是否在允许的群聊中
            allowed_groups = [
                g.strip() for g in verify_group_id.split(",") if g.strip()
            ]
            if allowed_groups and group_id not in allowed_groups:
                logger.info(f"群聊 {group_id} 不在允许的验证群列表中: {allowed_groups}")
                return
        else:
            # 私聊消息
            if not enable_private_verify:
                logger.info("私聊验证未启用，跳过")
                return

        user_id = event.get_sender_id()
        user_name = event.get_sender_name()

        success, result = await self.oidc_server.verify_code_submit(
            code, user_id, {"id": user_id, "name": user_name}
        )

        if success:
            yield event.plain_result(f"验证成功！您已通过OIDC认证。")
        else:
            yield event.plain_result(f"验证失败：{result}")

    @filter.regex(r"^\d{4,8}$")
    async def verify_code_direct(self, event: AstrMessageEvent):
        message_str = event.get_message_str().strip()

        if not message_str.isdigit():
            return

        if not self.oidc_server:
            return

        code = message_str
        logger.info(f"收到验证码: {code}")

        # 先检查验证码是否存在，避免不必要的群聊检查
        if code not in self.oidc_server.verify_codes:
            logger.info(
                f"验证码不存在: {code}, 当前验证码列表: {list(self.oidc_server.verify_codes.keys())}"
            )
            return

        # 检查群聊限制
        message_type = event.get_message_type()
        is_group = (
            message_type.value == "GroupMessage" or message_type.name == "GROUP_MESSAGE"
        )
        group_id = event.get_group_id() if is_group else ""
        enable_group_verify = self._get_web_config("enable_group_verify", True)
        enable_private_verify = self._get_web_config("enable_private_verify", True)
        verify_group_id = self._get_web_config("verify_group_id", "")

        logger.info(
            f"消息类型: {message_type}, is_group: {is_group}, group_id: {group_id}"
        )
        logger.info(
            f"群聊验证启用: {enable_group_verify}, 私聊验证启用: {enable_private_verify}, 允许的群: {verify_group_id}"
        )

        if is_group:
            # 群聊消息
            if not enable_group_verify:
                logger.info("群聊验证未启用，跳过")
                return
            # 检查是否在允许的群聊中
            allowed_groups = [
                g.strip() for g in verify_group_id.split(",") if g.strip()
            ]
            if allowed_groups and group_id not in allowed_groups:
                logger.info(f"群聊 {group_id} 不在允许的验证群列表中: {allowed_groups}")
                return
        else:
            # 私聊消息
            if not enable_private_verify:
                logger.info("私聊验证未启用，跳过")
                return

        user_id = event.get_sender_id()
        user_name = event.get_sender_name()

        success, result = await self.oidc_server.verify_code_submit(
            code, user_id, {"id": user_id, "name": user_name}
        )

        if success:
            yield event.plain_result(f"验证成功！您已通过OIDC认证。")
        else:
            yield event.plain_result(f"验证失败：{result}")
