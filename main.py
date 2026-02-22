"""
AstrBot OIDC 登录插件

用于网站 OIDC 登录插件，让支持 OIDC 登录的程序支持 QQ 群聊/私聊登录。

作者: 初叶🍂竹叶-Furry控
版本: v1.0.6
"""

import asyncio
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import jwt
from aiohttp import web

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools, register


def hash_password(password: str) -> str:
    """对密码进行哈希处理

    使用 PBKDF2-HMAC-SHA256 算法，这是 Python 标准库中提供的安全密码哈希方案。
    相比简单 SHA-256，PBKDF2 通过多次迭代（100,000次）增加暴力破解难度。

    格式: pbkdf2_sha256$iterations$salt$hash

    Args:
        password: 明文密码

    Returns:
        哈希后的密码
    """
    salt = secrets.token_hex(16)
    iterations = 100000  # 迭代次数，增加计算时间以抵抗暴力破解
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    ).hex()
    return f"pbkdf2_sha256${iterations}${salt}${pwd_hash}"


def verify_password(password: str, hashed: str) -> bool:
    """验证密码

    支持两种格式：
    1. 新的 PBKDF2 格式: pbkdf2_sha256$iterations$salt$hash
    2. 旧的 SHA-256 格式: salt:hash（向后兼容）

    安全说明：
    - 使用 hmac.compare_digest 进行常量时间比较，防止时序攻击
    - 无论密码是否正确，计算时间都保持一致

    Args:
        password: 明文密码
        hashed: 哈希后的密码

    Returns:
        是否匹配
    """
    try:
        # 检查是否为新的 PBKDF2 格式
        if hashed.startswith("pbkdf2_sha256$"):
            parts = hashed.split("$")
            if len(parts) != 4:
                return False
            iterations = int(parts[1])
            salt = parts[2]
            stored_hash = parts[3]
            pwd_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
            ).hex()
            # 使用常量时间比较防止时序攻击
            return hmac.compare_digest(pwd_hash, stored_hash)
        else:
            # 向后兼容：旧的 SHA-256 格式
            salt, stored_hash = hashed.split(":")
            pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            # 使用常量时间比较防止时序攻击
            return hmac.compare_digest(pwd_hash, stored_hash)
    except Exception:
        return False


def escape_html(text: str) -> str:
    """转义 HTML 特殊字符，防止 XSS 攻击（用于 HTML 内容）

    Args:
        text: 需要转义的文本

    Returns:
        转义后的安全文本
    """
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=False)


def escape_html_attr(text: str) -> str:
    """转义 HTML 属性值，防止 XSS 攻击（用于 HTML 属性）

    Args:
        text: 需要转义的文本

    Returns:
        转义后的安全文本
    """
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=True)


def escape_js_string(text: str) -> str:
    """转义 JavaScript 字符串，防止 XSS 攻击（用于 JS 字符串）

    Args:
        text: 需要转义的文本

    Returns:
        转义后的安全文本
    """
    if not isinstance(text, str):
        text = str(text)
    # 转义 JS 字符串中的特殊字符
    text = text.replace("\\", "\\\\")
    text = text.replace("'", "\\'")
    text = text.replace('"', '\\"')
    text = text.replace("\n", "\\n")
    text = text.replace("\r", "\\r")
    text = text.replace("\t", "\\t")
    return text


def escape_css_value(text: str) -> str:
    """转义 CSS 值，防止 XSS 攻击（用于 CSS 值）

    Args:
        text: 需要转义的文本

    Returns:
        转义后的安全文本
    """
    if not isinstance(text, str):
        text = str(text)
    # 移除 CSS 中的危险字符
    text = text.replace(";", "")
    text = text.replace("{", "")
    text = text.replace("}", "")
    text = text.replace("(", "")
    text = text.replace(")", "")
    text = text.replace("'", "")
    text = text.replace('"', "")
    return text


def validate_url(url: str) -> bool:
    """验证 URL 格式是否合法

    Args:
        url: 待验证的 URL

    Returns:
        是否合法
    """
    if not url:
        return True  # 空值允许（可选字段）
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def validate_color(color: str) -> bool:
    """验证 CSS 颜色值格式是否合法

    支持格式：
    - #RGB (如 #f0f)
    - #RRGGBB (如 #ff00ff)
    - #RGBA (如 #f0ff)
    - #RRGGBBAA (如 #ff00ff00)

    Args:
        color: 待验证的颜色值

    Returns:
        是否合法
    """
    if not color:
        return True  # 空值允许（使用默认值）
    return bool(
        re.match(
            r"^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{8})$", color
        )
    )


def validate_group_id(group_id: str) -> bool:
    """验证群号格式是否合法

    只允许数字和逗号（多个群号用逗号分隔）

    Args:
        group_id: 待验证的群号

    Returns:
        是否合法
    """
    if not group_id:
        return True  # 空值允许
    return bool(re.match(r"^[\d,]+$", group_id))


def validate_host_header(host: str) -> bool:
    """验证 Host header 是否合法，防止 Host Header 污染攻击

    Args:
        host: 请求的 Host header

    Returns:
        是否合法
    """
    if not host:
        return False
    # 只允许字母、数字、点、连字符和冒号（用于端口）
    # 格式：domain.com 或 domain.com:port
    import re

    pattern = r"^[a-zA-Z0-9.-]+(:\d+)?$"
    return bool(re.match(pattern, host))


# 导入模板管理器
try:
    from .templates import template_manager
except ImportError:
    # 如果模板模块不存在，创建一个简单的模板管理器
    class _TemplateManager:
        def __init__(self):
            self.templates_dir = os.path.join(os.path.dirname(__file__), "templates")

        def get_template(self, template_name: str) -> str:
            template_path = os.path.join(self.templates_dir, f"{template_name}.html")
            if not os.path.exists(template_path):
                raise FileNotFoundError(f"模板文件不存在: {template_path}")
            with open(template_path, encoding="utf-8") as f:
                return f.read()

        def render(self, template_name: str, **kwargs) -> str:
            template = self.get_template(template_name)
            return template.format(**kwargs)

    template_manager = _TemplateManager()


@dataclass
class AuthSession:
    """OIDC 认证会话数据类"""

    session_id: str
    code: str  # 验证码（用户输入的短码）
    auth_code: str  # OIDC 授权码（高熵随机字符串，用于交换 token）
    state: str
    redirect_uri: str
    created_at: float
    client_id: str = ""
    verified: bool = False
    verified_user_id: str | None = None
    user_info: dict = field(default_factory=dict)


@dataclass
class VerifyCode:
    """验证码数据类"""

    code: str
    session_id: str
    created_at: float
    used: bool = False


class AuditLogManager:
    """审计日志管理器

    记录关键操作日志，包括登录、授权、客户端管理等操作。
    数据存储在 AstrBot data 目录下，支持在管理后台查看。

    性能优化特性：
    - 按操作类型建立索引，加速过滤查询
    - 批量保存机制，减少磁盘I/O
    - 内存缓存，避免重复遍历
    """

    def __init__(self, data_dir: str):
        self.logs_file = os.path.join(data_dir, "audit_logs.json")
        self._logs: list = []
        self._max_logs = 1000  # 最多保留1000条日志
        self._action_index: dict[str, list] = {}  # 操作类型索引
        self._pending_logs: list = []  # 待保存的日志
        self._save_interval = 10  # 批量保存间隔（条）
        self._lock = asyncio.Lock()
        self._load_logs()
        self._rebuild_index()

    def _load_logs(self):
        """加载现有日志"""
        if os.path.exists(self.logs_file):
            try:
                with open(self.logs_file, encoding="utf-8") as f:
                    self._logs = json.load(f)
            except Exception as e:
                logger.error(f"加载审计日志失败: {e}")
                self._logs = []
        else:
            self._logs = []

    def _save_logs(self):
        """保存日志到文件"""
        try:
            with open(self.logs_file, "w", encoding="utf-8") as f:
                json.dump(self._logs, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存审计日志失败: {e}")

    def _rebuild_index(self):
        """重建操作类型索引"""
        self._action_index = {}
        for i, log in enumerate(self._logs):
            action = log.get("action")
            if action:
                if action not in self._action_index:
                    self._action_index[action] = []
                self._action_index[action].append(i)

    def _add_to_index(self, log_entry: dict, index: int):
        """添加日志到索引"""
        action = log_entry.get("action")
        if action:
            if action not in self._action_index:
                self._action_index[action] = []
            self._action_index[action].append(index)

    async def _flush_pending_logs(self):
        """批量保存待处理的日志"""
        async with self._lock:
            if not self._pending_logs:
                return

            # 将待处理日志添加到主日志列表
            for log_entry in self._pending_logs:
                self._logs.insert(0, log_entry)

            # 重建索引（因为使用了 insert(0)，所有索引位置都变了）
            self._rebuild_index()

            # 限制日志数量
            if len(self._logs) > self._max_logs:
                self._logs = self._logs[: self._max_logs]
                self._rebuild_index()

            # 保存到文件
            self._save_logs()

            # 清空待处理列表
            count = len(self._pending_logs)
            self._pending_logs = []
            logger.debug(f"批量保存了 {count} 条审计日志")

    def log(self, action: str, details: str = "", user: str = "", ip: str = ""):
        """记录一条审计日志

        Args:
            action: 操作类型，如 LOGIN, LOGOUT, CLIENT_ADD, CLIENT_UPDATE, CLIENT_DELETE, CONFIG_UPDATE, AUTHORIZE, TOKEN_EXCHANGE
            details: 操作详情
            user: 操作用户
            ip: 操作者IP地址
        """
        # 对敏感信息进行脱敏处理
        sanitized_details = LogSanitizer.sanitize(details)
        sanitized_user = LogSanitizer.sanitize(user)

        log_entry = {
            "timestamp": time.time(),
            "datetime": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": sanitized_details,
            "user": sanitized_user,
            "ip": ip,
        }

        # 添加到待处理列表
        self._pending_logs.append(log_entry)

        # 达到批量保存阈值时立即保存
        if len(self._pending_logs) >= self._save_interval:
            # 使用 create_task 异步执行保存
            try:
                asyncio.create_task(self._flush_pending_logs())
            except RuntimeError:
                # 如果没有事件循环，同步保存所有待处理日志
                for pending_entry in self._pending_logs:
                    self._logs.insert(0, pending_entry)
                    self._add_to_index(pending_entry, 0)
                if len(self._logs) > self._max_logs:
                    self._logs = self._logs[: self._max_logs]
                    self._rebuild_index()
                self._save_logs()
                self._pending_logs = []

    async def flush(self):
        """强制保存所有待处理的日志"""
        await self._flush_pending_logs()

    def get_logs(
        self, limit: int = 100, offset: int = 0, action_filter: str = None
    ) -> list:
        """获取日志列表

        Args:
            limit: 返回的最大条数
            offset: 跳过前多少条
            action_filter: 按操作类型过滤

        Returns:
            日志列表（使用索引加速过滤）
        """
        # 先刷新待处理日志
        if self._pending_logs:
            try:
                asyncio.create_task(self._flush_pending_logs())
            except RuntimeError:
                pass

        if action_filter and action_filter in self._action_index:
            # 使用索引快速获取指定类型的日志
            indices = self._action_index[action_filter]
            filtered_logs = [self._logs[i] for i in indices]
            return filtered_logs[offset : offset + limit]
        elif action_filter:
            # 索引中没有该类型，返回空列表
            return []
        else:
            # 返回所有日志
            return self._logs[offset : offset + limit]

    def get_logs_count(self, action_filter: str = None) -> int:
        """获取日志总数（使用索引加速）"""
        if action_filter:
            return len(self._action_index.get(action_filter, []))
        return len(self._logs) + len(self._pending_logs)

    def clear_logs(self):
        """清空所有日志"""
        self._logs = []
        self._pending_logs = []
        self._action_index = {}
        self._save_logs()


class KeyManager:
    """密钥管理器

    管理 RSA 密钥对的生成、轮换和版本控制。
    支持密钥轮换机制，定期更新密钥以提高安全性。
    """

    def __init__(
        self,
        data_dir: str,
        key_size: int = 2048,
        rotation_days: int = 90,
        keep_old_keys: int = 2,
    ):
        """初始化密钥管理器

        Args:
            data_dir: 数据目录路径
            key_size: RSA 密钥长度（默认2048位）
            rotation_days: 密钥轮换周期（天，默认90天）
            keep_old_keys: 保留的旧密钥数量（默认2个）
        """
        self.data_dir = data_dir
        self.key_size = key_size
        self.rotation_days = rotation_days
        self.keep_old_keys = keep_old_keys
        self._keys: dict[
            str, dict
        ] = {}  # key_id -> {private_key, public_key, created_at, is_active}
        self._current_key_id: str = ""
        self._lock = asyncio.Lock()
        self._load_keys()

    def _load_keys(self):
        """加载所有密钥"""
        keys_file = os.path.join(self.data_dir, "keys.json")
        if os.path.exists(keys_file):
            try:
                with open(keys_file, encoding="utf-8") as f:
                    data = json.load(f)
                    self._current_key_id = data.get("current_key_id", "")
                    # 加载密钥元数据
                    for key_id, key_info in data.get("keys", {}).items():
                        private_key_path = os.path.join(
                            self.data_dir, f"private_key_{key_id}.pem"
                        )
                        public_key_path = os.path.join(
                            self.data_dir, f"public_key_{key_id}.pem"
                        )
                        if os.path.exists(private_key_path) and os.path.exists(
                            public_key_path
                        ):
                            # 检查私钥文件权限
                            try:
                                file_mode = os.stat(private_key_path).st_mode
                                if file_mode & 0o077 != 0:
                                    logger.warning(
                                        f"私钥文件 {private_key_path} 权限不安全，建议设置为 0600"
                                    )
                            except Exception as e:
                                logger.warning(f"检查私钥文件权限失败: {e}")

                            self._keys[key_id] = {
                                "created_at": key_info.get("created_at", 0),
                                "is_active": key_info.get("is_active", True),
                            }
                logger.info(
                    f"已加载 {len(self._keys)} 个密钥，当前密钥: {self._current_key_id}"
                )
            except Exception as e:
                logger.error(f"加载密钥配置失败: {e}")

        # 如果没有密钥，生成新的
        if not self._keys:
            self._generate_new_key()

    def _save_keys_config(self):
        """保存密钥配置"""
        keys_file = os.path.join(self.data_dir, "keys.json")
        data = {
            "current_key_id": self._current_key_id,
            "keys": {
                key_id: {
                    "created_at": info["created_at"],
                    "is_active": info["is_active"],
                }
                for key_id, info in self._keys.items()
            },
        }
        try:
            with open(keys_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存密钥配置失败: {e}")

    def _generate_new_key(self) -> str:
        """生成新的 RSA 密钥对

        Returns:
            新生成的密钥ID
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # 使用纳秒级时间戳 + 随机数避免冲突
        key_id = f"key_{int(time.time_ns())}_{secrets.token_hex(4)}"
        logger.info(f"生成新的 RSA 密钥对: {key_id}")

        # 生成密钥
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size, backend=default_backend()
        )
        public_key = private_key.public_key()

        # 保存私钥
        private_key_path = os.path.join(self.data_dir, f"private_key_{key_id}.pem")
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        # 设置私钥文件权限为 0600（仅所有者可读写）
        try:
            os.chmod(private_key_path, 0o600)
        except Exception as e:
            logger.warning(f"设置私钥文件权限失败: {e}")

        # 保存公钥
        public_key_path = os.path.join(self.data_dir, f"public_key_{key_id}.pem")
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        # 更新密钥记录
        self._keys[key_id] = {
            "created_at": time.time(),
            "is_active": True,
        }
        self._current_key_id = key_id
        self._save_keys_config()

        logger.info(f"新密钥已生成: {key_id}")
        return key_id

    def _load_key(self, key_id: str) -> tuple:
        """加载指定密钥

        Returns:
            (private_key, public_key) 或 (None, None)
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        private_key_path = os.path.join(self.data_dir, f"private_key_{key_id}.pem")
        public_key_path = os.path.join(self.data_dir, f"public_key_{key_id}.pem")

        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            return None, None

        try:
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            return private_key, public_key
        except Exception as e:
            logger.error(f"加载密钥 {key_id} 失败: {e}")
            return None, None

    def get_current_key(self) -> tuple[str, Any, Any]:
        """获取当前使用的密钥

        Returns:
            (key_id, private_key, public_key)
        """
        private_key, public_key = self._load_key(self._current_key_id)
        if private_key is None:
            # 当前密钥加载失败，生成新的
            key_id = self._generate_new_key()
            private_key, public_key = self._load_key(key_id)
            return key_id, private_key, public_key
        return self._current_key_id, private_key, public_key

    def get_key(self, key_id: str) -> tuple[Any, Any]:
        """获取指定密钥

        Returns:
            (private_key, public_key) 或 (None, None)
        """
        return self._load_key(key_id)

    def get_all_public_keys(self) -> list[dict]:
        """获取所有公钥（包括非活跃密钥，用于 JWKS）

        安全说明：
        - 返回所有密钥（包括 is_active=False 的密钥）
        - 这是必要的，因为旧 Token（1小时有效期）可能仍在使用
        - 客户端需要能够验证这些旧 Token 的签名
        - 密钥轮换后，旧公钥仍需在 JWKS 中保留一段时间

        Returns:
            公钥列表，每个包含 key_id 和公钥对象
        """
        keys = []
        for key_id, info in self._keys.items():
            # 返回所有密钥，不只是活跃密钥
            # 这是 OIDC 规范要求，确保旧 Token 仍可验证
            _, public_key = self._load_key(key_id)
            if public_key:
                keys.append({"key_id": key_id, "public_key": public_key})
        return keys

    async def rotate_keys(self) -> bool:
        """执行密钥轮换

        如果当前密钥超过轮换周期，则生成新密钥并标记旧密钥为不活跃。

        性能说明：
        - 使用 run_in_executor 将 CPU 密集型操作放到线程池执行
        - 避免阻塞异步事件循环

        Returns:
            是否执行了轮换
        """
        async with self._lock:
            current_key = self._keys.get(self._current_key_id)
            if not current_key:
                return False

            created_at = current_key.get("created_at", 0)
            rotation_seconds = self.rotation_days * 24 * 3600

            if time.time() - created_at < rotation_seconds:
                # 未达到轮换时间
                return False

            logger.info("执行密钥轮换...")

            # 标记当前密钥为不活跃
            current_key["is_active"] = False

            # 使用 run_in_executor 将 CPU 密集型操作放到线程池执行
            # 避免阻塞异步事件循环
            loop = asyncio.get_event_loop()
            new_key_id = await loop.run_in_executor(None, self._generate_new_key)

            # 清理过期的旧密钥
            await self._cleanup_old_keys()

            self._save_keys_config()
            logger.info(f"密钥轮换完成，新密钥: {new_key_id}")
            return True

    async def _cleanup_old_keys(self):
        """清理过期的旧密钥，只保留最近的几个"""
        inactive_keys = [
            (key_id, info)
            for key_id, info in self._keys.items()
            if not info.get("is_active", True)
        ]

        # 按创建时间排序，保留最新的
        inactive_keys.sort(key=lambda x: x[1].get("created_at", 0), reverse=True)

        keys_to_remove = inactive_keys[self.keep_old_keys :]
        for key_id, _ in keys_to_remove:
            logger.info(f"清理旧密钥: {key_id}")
            del self._keys[key_id]

            # 删除密钥文件
            private_key_path = os.path.join(self.data_dir, f"private_key_{key_id}.pem")
            public_key_path = os.path.join(self.data_dir, f"public_key_{key_id}.pem")
            try:
                if os.path.exists(private_key_path):
                    os.remove(private_key_path)
                if os.path.exists(public_key_path):
                    os.remove(public_key_path)
            except Exception as e:
                logger.error(f"删除旧密钥文件失败 {key_id}: {e}")

    def get_key_info(self) -> dict:
        """获取密钥信息（用于管理后台显示）"""
        current_key = self._keys.get(self._current_key_id, {})
        return {
            "current_key_id": self._current_key_id,
            "total_keys": len(self._keys),
            "active_keys": sum(
                1 for k in self._keys.values() if k.get("is_active", True)
            ),
            "current_key_created": current_key.get("created_at", 0),
            "rotation_days": self.rotation_days,
            "next_rotation": current_key.get("created_at", 0)
            + self.rotation_days * 24 * 3600,
        }


class LogSanitizer:
    """日志脱敏工具

    用于对日志中的敏感信息进行脱敏处理，防止敏感数据泄露。
    """

    # 敏感字段列表
    SENSITIVE_FIELDS = [
        "password",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "secret",
        "client_secret",
        "code",
        "auth_code",
        "authorization",
        "cookie",
        "session",
        "private_key",
        "api_key",
    ]

    # 敏感模式（正则表达式）
    SENSITIVE_PATTERNS = [
        # JWT Token
        (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "[JWT_TOKEN]"),
        # Bearer Token
        (r"Bearer\s+[a-zA-Z0-9_-]+", "Bearer [TOKEN]"),
        # API Key / Secret
        (
            r'(api[_-]?key|secret)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}',
            r"\1=[REDACTED]",
        ),
        # 邮箱地址
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL]"),
        # IP地址（可选脱敏）
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]"),
    ]

    @classmethod
    def sanitize(cls, message: str) -> str:
        """对日志消息进行脱敏处理

        Args:
            message: 原始日志消息

        Returns:
            脱敏后的消息
        """
        if not isinstance(message, str):
            message = str(message)

        result = message

        # 应用正则表达式脱敏
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            try:
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
            except re.error:
                continue

        return result

    @classmethod
    def sanitize_dict(cls, data: dict, max_depth: int = 3) -> dict:
        """对字典中的敏感字段进行脱敏

        Args:
            data: 原始字典
            max_depth: 最大递归深度

        Returns:
            脱敏后的字典副本
        """
        if max_depth <= 0:
            return data

        result = {}
        for key, value in data.items():
            key_lower = str(key).lower()

            # 检查是否为敏感字段
            is_sensitive = any(
                sensitive in key_lower for sensitive in cls.SENSITIVE_FIELDS
            )

            if is_sensitive:
                if isinstance(value, str):
                    if len(value) > 8:
                        result[key] = value[:4] + "****" + value[-4:]
                    else:
                        result[key] = "****"
                else:
                    result[key] = "[REDACTED]"
            elif isinstance(value, dict):
                result[key] = cls.sanitize_dict(value, max_depth - 1)
            elif isinstance(value, list):
                result[key] = cls.sanitize_list(value, max_depth - 1)
            else:
                result[key] = value

        return result

    @classmethod
    def sanitize_list(cls, data: list, max_depth: int = 3) -> list:
        """对列表中的敏感数据进行脱敏"""
        if max_depth <= 0:
            return data

        result = []
        for item in data:
            if isinstance(item, dict):
                result.append(cls.sanitize_dict(item, max_depth - 1))
            elif isinstance(item, list):
                result.append(cls.sanitize_list(item, max_depth - 1))
            else:
                result.append(item)
        return result


class SessionManager:
    """会话管理器

    管理 OIDC 认证会话、验证码和访问令牌的持久化存储。
    数据存储在 AstrBot data 目录下，重启后不会丢失。
    """

    def __init__(self, data_dir: str):
        self.sessions_file = os.path.join(data_dir, "sessions.json")
        self.verify_codes_file = os.path.join(data_dir, "verify_codes.json")
        self.access_tokens_file = os.path.join(data_dir, "access_tokens.json")
        self._sessions: dict = {}
        self._verify_codes: dict = {}
        self._access_tokens: dict = {}
        self._lock = asyncio.Lock()
        self._load_all()

    def _load_all(self):
        """加载所有会话数据"""
        self._sessions = self._load_json(self.sessions_file)
        self._verify_codes = self._load_json(self.verify_codes_file)
        self._access_tokens = self._load_json(self.access_tokens_file)
        logger.info(
            f"已加载会话数据: {len(self._sessions)} 个会话, "
            f"{len(self._verify_codes)} 个验证码, {len(self._access_tokens)} 个令牌"
        )

    def _load_json(self, filepath: str) -> dict:
        """加载 JSON 文件"""
        if os.path.exists(filepath):
            try:
                with open(filepath, encoding="utf-8") as f:
                    data = json.load(f)
                    return data
            except Exception as e:
                logger.error(f"加载文件失败 {filepath}: {e}")
                return {}
        return {}

    def _save_json(self, filepath: str, data: dict):
        """保存 JSON 文件"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            logger.error(f"保存文件失败 {filepath}: {e}")

    async def save_sessions(self):
        """保存会话数据（异步）"""
        async with self._lock:
            self._save_json(self.sessions_file, self._sessions)

    async def save_verify_codes(self):
        """保存验证码数据（异步）"""
        async with self._lock:
            self._save_json(self.verify_codes_file, self._verify_codes)

    async def save_access_tokens(self):
        """保存访问令牌数据（异步）"""
        async with self._lock:
            self._save_json(self.access_tokens_file, self._access_tokens)

    async def save_all(self):
        """保存所有数据"""
        async with self._lock:
            self._save_json(self.sessions_file, self._sessions)
            self._save_json(self.verify_codes_file, self._verify_codes)
            self._save_json(self.access_tokens_file, self._access_tokens)

    # 会话操作
    def get_session(self, session_id: str) -> dict | None:
        return self._sessions.get(session_id)

    def set_session(self, session_id: str, session_data: dict):
        self._sessions[session_id] = session_data

    def delete_session(self, session_id: str):
        self._sessions.pop(session_id, None)

    def get_all_sessions(self) -> dict:
        return self._sessions.copy()

    # 验证码操作
    def get_verify_code(self, code: str) -> dict | None:
        return self._verify_codes.get(code)

    def set_verify_code(self, code: str, verify_data: dict):
        self._verify_codes[code] = verify_data

    def delete_verify_code(self, code: str):
        self._verify_codes.pop(code, None)

    def get_all_verify_codes(self) -> dict:
        return self._verify_codes.copy()

    # 访问令牌操作
    def get_access_token(self, token: str) -> dict | None:
        return self._access_tokens.get(token)

    def set_access_token(self, token: str, token_data: dict):
        self._access_tokens[token] = token_data

    def delete_access_token(self, token: str):
        self._access_tokens.pop(token, None)

    def get_all_access_tokens(self) -> dict:
        return self._access_tokens.copy()


class ConfigManager:
    """Web 配置管理器

    管理插件的 Web 端配置，包括验证码设置、主题设置等。
    数据存储在 AstrBot data 目录下，防止更新/重装插件时数据丢失。
    """

    def __init__(self, plugin):
        self.plugin = plugin
        # 数据存储在 AstrBot data 目录下，防止更新/重装插件时数据丢失
        self.data_dir = StarTools.get_data_dir() / "chuyeoidc"
        os.makedirs(self.data_dir, exist_ok=True)
        self.config_file = self.data_dir / "web_config.json"
        self._web_config: dict = {}
        self._load_config()

    def _load_config(self):
        default_config = {
            "enable_group_verify": True,
            "enable_private_verify": True,
            "verify_group_id": "",
            "code_expire_seconds": 300,
            "code_length": 6,
            "theme_color": "#50b6fe",
            "icon_url": "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
            "favicon_url": "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%BA%95.png",
            "jwt_secret": "",  # JWT 签名密钥，留空则自动生成
            "public_url": "",  # 公共访问URL，用于OIDC issuer，如 https://example.com
        }

        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, encoding="utf-8") as f:
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
        self.data_dir = StarTools.get_data_dir() / "chuyeoidc"
        os.makedirs(self.data_dir, exist_ok=True)
        self.clients_file = self.data_dir / "clients.json"
        self._clients: dict[str, dict] = {}
        self._load_clients()

    def _load_clients(self):
        if os.path.exists(self.clients_file):
            try:
                with open(self.clients_file, encoding="utf-8") as f:
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

    def get_client(self, client_id: str) -> dict | None:
        return self._clients.get(client_id)

    def verify_client(self, client_id: str, client_secret: str) -> bool:
        """验证客户端凭据

        安全说明：
        - 使用 hmac.compare_digest 进行常量时间比较，防止时序攻击
        - 即使客户端不存在，也执行一次虚拟比较，确保时间一致
        """
        client = self._clients.get(client_id)
        if not client:
            # 执行虚拟比较，防止时序攻击（攻击者通过响应时间判断 client_id 是否存在）
            hmac.compare_digest("dummy_secret", client_secret)
            return False
        stored_secret = client.get("client_secret", "")
        # 使用常量时间比较防止时序攻击
        return hmac.compare_digest(client_secret, stored_secret)

    def add_client(
        self,
        client_id: str,
        client_secret: str,
        name: str = "",
        home_urls: list = None,
        redirect_urls: list = None,
    ) -> bool:
        if client_id in self._clients:
            return False
        self._clients[client_id] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "name": name or client_id,
            "home_urls": home_urls if home_urls else [],
            "redirect_urls": redirect_urls if redirect_urls else [],
            "created_at": time.time(),
        }
        return self._save_clients()

    def update_client(
        self,
        client_id: str,
        client_secret: str = None,
        name: str = None,
        home_urls: list = None,
        redirect_urls: list = None,
    ) -> bool:
        if client_id not in self._clients:
            return False
        if client_secret is not None:
            self._clients[client_id]["client_secret"] = client_secret
        if name is not None:
            self._clients[client_id]["name"] = name
        if home_urls is not None:
            self._clients[client_id]["home_urls"] = home_urls
        if redirect_urls is not None:
            self._clients[client_id]["redirect_urls"] = redirect_urls
        return self._save_clients()

    def verify_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """验证 redirect_uri 是否匹配客户端注册的任一 redirect_url"""
        client = self._clients.get(client_id)
        if not client:
            return False
        redirect_urls = client.get("redirect_urls", [])
        if not redirect_urls:
            # 兼容旧数据，使用单个 redirect_url
            old_url = client.get("redirect_url", "")
            if old_url:
                redirect_urls = [old_url]
        return redirect_uri in redirect_urls

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
        """生成客户端名称

        安全说明：
        - 使用 secrets.choice 替代 random.choices，确保密码学安全
        """
        chars = string.ascii_letters + string.digits
        return f"OIDC_{''.join(secrets.choice(chars) for _ in range(5))}"


class OIDCServer:
    """OIDC 服务端核心类

    处理 OIDC 协议相关的所有逻辑，包括：
    - 认证会话管理
    - 验证码生成和验证
    - Access Token 生成和验证
    - 用户信息获取
    """

    def __init__(
        self,
        plugin,
        config_manager: ConfigManager,
        client_manager: ClientManager,
        session_manager: SessionManager,
    ):
        self.plugin = plugin
        self.config_manager = config_manager
        self.client_manager = client_manager
        self.session_manager = session_manager
        self.app: web.Application | None = None
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self._lock = asyncio.Lock()
        self._jwt_algorithm = "RS256"  # 使用 RS256 非对称加密
        # 初始化密钥管理器
        self.key_manager = KeyManager(
            data_dir=self.config_manager.data_dir,
            key_size=2048,
            rotation_days=90,
            keep_old_keys=2,
        )
        # 启动自动保存任务
        self._save_task: asyncio.Task | None = None
        self._start_auto_save()

    def get_issuer(self) -> str:
        """获取 OIDC issuer

        从配置的 public_url 获取，确保安全性。
        如果未配置，返回空字符串（由 discovery 端点处理）。
        """
        public_url = self.config_manager.get("public_url", "")
        return public_url.rstrip("/") if public_url else ""

    def _get_rsa_private_key_pem(self) -> str:
        """获取 RSA 私钥 PEM 格式（用于 JWT 签名）"""
        from cryptography.hazmat.primitives import serialization

        _, private_key, _ = self.key_manager.get_current_key()
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def _get_rsa_public_key_pem(self) -> str:
        """获取 RSA 公钥 PEM 格式"""
        from cryptography.hazmat.primitives import serialization

        _, _, public_key = self.key_manager.get_current_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def _get_jwks_keys(self) -> list[dict]:
        """获取 JWKS 格式的所有活跃公钥（不包含私钥信息）"""
        import base64

        def int_to_base64url(value: int) -> str:
            """将整数转换为 Base64URL 编码"""
            byte_length = (value.bit_length() + 7) // 8
            bytes_value = value.to_bytes(byte_length, "big")
            return base64.urlsafe_b64encode(bytes_value).decode("ascii").rstrip("=")

        keys = []
        all_public_keys = self.key_manager.get_all_public_keys()

        for key_info in all_public_keys:
            key_id = key_info["key_id"]
            public_key = key_info["public_key"]

            # 获取公钥的原始组件
            public_numbers = public_key.public_numbers()
            n = public_numbers.n
            e = public_numbers.e

            keys.append(
                {
                    "kty": "RSA",
                    "kid": key_id,
                    "alg": self._jwt_algorithm,
                    "use": "sig",
                    "n": int_to_base64url(n),
                    "e": int_to_base64url(e),
                }
            )

        return keys

    def _get_jwks_key(self) -> dict:
        """获取当前使用的 JWKS 格式公钥（向后兼容）"""
        keys = self._get_jwks_keys()
        if keys:
            return keys[0]  # 返回第一个（当前）密钥
        return {}

    def _start_auto_save(self):
        """启动自动保存任务，每30秒保存一次会话数据"""

        async def auto_save():
            while True:
                try:
                    await asyncio.sleep(30)  # 每30秒保存一次
                    await self.session_manager.save_all()
                    logger.debug("会话数据已自动保存")
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"自动保存会话数据失败: {e}")

        self._save_task = asyncio.create_task(auto_save())

    def stop_auto_save(self):
        """停止自动保存任务"""
        if self._save_task:
            self._save_task.cancel()

    async def save_all_data(self):
        """立即保存所有会话数据"""
        await self.session_manager.save_all()

    # 数据访问属性（兼容旧代码）
    @property
    def sessions(self) -> dict:
        """获取所有会话（从 SessionManager 加载）"""
        return self.session_manager.get_all_sessions()

    @property
    def verify_codes(self) -> dict:
        """获取所有验证码（从 SessionManager 加载）"""
        return self.session_manager.get_all_verify_codes()

    @property
    def access_tokens(self) -> dict:
        """获取所有访问令牌（从 SessionManager 加载）"""
        return self.session_manager.get_all_access_tokens()

    def _get_config(self, key: str, default=None):
        return self.plugin._get_config(key, default)

    def _get_web_config(self, key: str, default=None):
        return self.config_manager.get(key, default)

    def _generate_code(self, length: int = 6) -> str:
        """生成验证码

        安全说明：
        - 使用 secrets.choice 替代 random.choices，确保密码学安全
        - secrets 模块使用操作系统提供的安全随机数源
        """
        return "".join(secrets.choice(string.digits) for _ in range(length))

    def _generate_token(self) -> str:
        return secrets.token_urlsafe(32)

    def _generate_id_token(self, session: AuthSession) -> str:
        """生成标准 JWT 格式的 id_token

        遵循 OIDC 规范，包含必要的 claims：
        - iss: 签发者
        - sub: 用户唯一标识
        - aud: 受众（client_id）
        - exp: 过期时间（整数时间戳）
        - iat: 签发时间（整数时间戳）
        - auth_time: 认证时间（整数时间戳）

        注意：根据 OIDC 规范，时间字段应为整数时间戳，而非浮点数
        """
        now = datetime.now(timezone.utc)
        now_ts = int(now.timestamp())
        expires = now_ts + 3600

        payload = {
            "iss": self.get_issuer(),
            "sub": session.verified_user_id or "",
            "aud": session.client_id or "",
            "exp": expires,
            "iat": now_ts,
            "auth_time": now_ts,
            "name": session.user_info.get("name", ""),
            "nickname": session.user_info.get("nickname", ""),
            "email": session.user_info.get("email", ""),
        }

        # 获取当前密钥ID用于JWT头部
        current_key_id, _, _ = self.key_manager.get_current_key()
        token = jwt.encode(
            payload,
            self._get_rsa_private_key_pem(),
            algorithm=self._jwt_algorithm,
            headers={"kid": current_key_id},
        )
        return token

    async def create_auth_session(
        self, redirect_uri: str, state: str, client_id: str = ""
    ) -> tuple[str, str, str]:
        session_id = str(uuid.uuid4())
        code_length = self._get_web_config("code_length", 6)
        verify_code = self._generate_code(code_length)
        # 生成高熵 OIDC 授权码（与验证码分离）
        auth_code = secrets.token_urlsafe(32)

        logger.info(f"创建认证会话: session_id={session_id[:8]}...")

        async with self._lock:
            session = AuthSession(
                session_id=session_id,
                code=verify_code,
                auth_code=auth_code,
                state=state,
                redirect_uri=redirect_uri,
                created_at=time.time(),
                client_id=client_id,
            )
            # 使用 SessionManager 存储会话
            self.session_manager.set_session(session_id, self._session_to_dict(session))
            self.session_manager.set_verify_code(
                verify_code,
                {
                    "code": verify_code,
                    "session_id": session_id,
                    "created_at": time.time(),
                    "used": False,
                },
            )
            logger.info(
                f"会话已存储: sessions count={len(self.sessions)}, verify_codes count={len(self.verify_codes)}"
            )

        return session_id, verify_code, auth_code

    def _session_to_dict(self, session: AuthSession) -> dict:
        """将 AuthSession 转换为字典"""
        return {
            "session_id": session.session_id,
            "code": session.code,
            "auth_code": session.auth_code,
            "state": session.state,
            "redirect_uri": session.redirect_uri,
            "created_at": session.created_at,
            "client_id": session.client_id,
            "verified": session.verified,
            "verified_user_id": session.verified_user_id,
            "user_info": session.user_info,
        }

    def _dict_to_session(self, data: dict) -> AuthSession:
        """将字典转换为 AuthSession"""
        return AuthSession(
            session_id=data["session_id"],
            code=data["code"],
            auth_code=data["auth_code"],
            state=data["state"],
            redirect_uri=data["redirect_uri"],
            created_at=data["created_at"],
            client_id=data.get("client_id", ""),
            verified=data.get("verified", False),
            verified_user_id=data.get("verified_user_id"),
            user_info=data.get("user_info", {}),
        )

    def _dict_to_verify_code(self, data: dict) -> VerifyCode:
        """将字典转换为 VerifyCode"""
        return VerifyCode(
            code=data["code"],
            session_id=data["session_id"],
            created_at=data["created_at"],
            used=data.get("used", False),
        )

    async def verify_code_submit(
        self, code: str, user_id: str, user_info: dict = None
    ) -> tuple[bool, str]:
        """提交验证码进行验证

        Args:
            code: 验证码
            user_id: 用户ID
            user_info: 用户信息

        Returns:
            (是否成功, session_id 或错误信息)

        安全说明：
        - 如果 session 不存在，返回失败（防止状态不一致）
        - 验证码使用后立即标记，防止重放攻击
        """
        expire_seconds = self._get_web_config("code_expire_seconds", 300)

        async with self._lock:
            verify_code_data = self.session_manager.get_verify_code(code)
            if not verify_code_data:
                logger.warning(f"验证码不存在: {code[:3]}...")
                return False, "验证码不存在"

            verify_code = self._dict_to_verify_code(verify_code_data)

            if verify_code.used:
                return False, "验证码已使用"

            if time.time() - verify_code.created_at > expire_seconds:
                self.session_manager.delete_verify_code(code)
                self.session_manager.delete_session(verify_code.session_id)
                return False, "验证码已过期"

            # 先检查 session 是否存在
            session_data = self.session_manager.get_session(verify_code.session_id)
            if not session_data:
                logger.error(
                    f"Session不存在: session_id={verify_code.session_id[:8]}..."
                )
                # Session 不存在，清理验证码防止状态不一致
                self.session_manager.delete_verify_code(code)
                return False, "会话不存在或已过期"

            # 更新验证码状态
            verify_code_data["used"] = True
            self.session_manager.set_verify_code(code, verify_code_data)

            # 更新会话状态
            session_data["verified"] = True
            session_data["verified_user_id"] = user_id
            session_data["user_info"] = user_info or {
                "id": user_id,
                "name": user_id,
            }
            self.session_manager.set_session(verify_code.session_id, session_data)
            logger.info(f"验证成功: session_id={verify_code.session_id[:8]}...")

            return True, verify_code.session_id

    async def get_session(self, session_id: str) -> AuthSession | None:
        logger.info(
            f"get_session: session_id={session_id[:8]}..., sessions count={len(self.sessions)}, keys={list(self.sessions.keys())[:5]}"
        )
        session_data = self.session_manager.get_session(session_id)
        if session_data:
            return self._dict_to_session(session_data)
        return None

    async def exchange_code(
        self, code: str, client_id: str = "", redirect_uri: str = ""
    ) -> dict | None:
        logger.info(
            f"exchange_code: client_id={client_id}, redirect_uri={redirect_uri}"
        )
        async with self._lock:
            session = None
            session_id = None
            # 遍历所有会话查找匹配的 auth_code
            for sid, session_data in self.sessions.items():
                # 使用 auth_code（高熵授权码）而不是 code（验证码）
                if session_data.get("auth_code") == code and session_data.get(
                    "verified"
                ):
                    session = self._dict_to_session(session_data)
                    session_id = sid
                    break

            if not session:
                logger.warning("未找到匹配的session")
                return None

            if client_id and session.client_id and session.client_id != client_id:
                logger.warning(
                    f"client_id不匹配: expected={session.client_id[:8] if session.client_id else 'any'}..., got={client_id[:8]}..."
                )
                return None

            # 验证 redirect_uri 是否与授权时一致（OIDC 安全要求）
            if redirect_uri and session.redirect_uri != redirect_uri:
                logger.warning(
                    f"redirect_uri不匹配: expected={session.redirect_uri}, got={redirect_uri}"
                )
                return None

            # 防止授权码重放：立即删除会话，使授权码失效
            self.session_manager.delete_session(session_id)

            access_token = self._generate_token()
            refresh_token = self._generate_token()
            # 使用 JWT 格式的 id_token
            id_token = self._generate_id_token(session)

            token_data = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": refresh_token,
                "id_token": id_token,
            }
            # 使用 SessionManager 存储令牌
            self.session_manager.set_access_token(
                access_token,
                {
                    **token_data,
                    "created_at": time.time(),
                    "user_id": session.verified_user_id,
                    "user_info": session.user_info,
                    "client_id": client_id,
                },
            )
            # 存储 refresh_token 关联信息
            self.session_manager.set_access_token(
                refresh_token,
                {
                    "type": "refresh_token",
                    "access_token": access_token,
                    "user_id": session.verified_user_id,
                    "user_info": session.user_info,
                    "client_id": client_id,
                    "created_at": time.time(),
                },
            )

            logger.info(f"Token交换成功: client_id={client_id}")
            return token_data

    async def exchange_refresh_token(
        self, refresh_token: str, client_id: str = ""
    ) -> dict | None:
        """使用 refresh_token 换取新的 access_token"""
        async with self._lock:
            token_data = self.session_manager.get_access_token(refresh_token)
            if not token_data or token_data.get("type") != "refresh_token":
                return None

            # 验证 client_id
            if (
                client_id
                and token_data.get("client_id")
                and token_data.get("client_id") != client_id
            ):
                return None

            # 检查 refresh_token 是否过期（30天）
            if time.time() - token_data.get("created_at", 0) > 30 * 24 * 3600:
                self.session_manager.delete_access_token(refresh_token)
                return None

            # 生成新的 token
            new_access_token = self._generate_token()
            new_refresh_token = self._generate_token()

            user_id = token_data.get("user_id", "")
            user_info = token_data.get("user_info", {})
            stored_client_id = token_data.get("client_id", "")

            # 删除旧的 refresh_token
            self.session_manager.delete_access_token(refresh_token)

            # 存储新的 token
            new_token_data = {
                "access_token": new_access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": new_refresh_token,
            }
            self.session_manager.set_access_token(
                new_access_token,
                {
                    **new_token_data,
                    "created_at": time.time(),
                    "user_id": user_id,
                    "user_info": user_info,
                    "client_id": stored_client_id,
                },
            )
            self.session_manager.set_access_token(
                new_refresh_token,
                {
                    "type": "refresh_token",
                    "access_token": new_access_token,
                    "user_id": user_id,
                    "user_info": user_info,
                    "client_id": stored_client_id,
                    "created_at": time.time(),
                },
            )

            return new_token_data

    async def get_user_info(self, token: str) -> dict | None:
        token_data = self.session_manager.get_access_token(token)
        if not token_data:
            return None
        # 拒绝 refresh_token，只允许 access_token 获取用户信息
        if token_data.get("type") == "refresh_token":
            logger.warning("拒绝使用 refresh_token 获取用户信息")
            return None
        return token_data

    async def cleanup_expired(self):
        expire_seconds = self._get_web_config("code_expire_seconds", 300)
        current_time = time.time()

        async with self._lock:
            expired_codes = [
                code
                for code, vc in self.verify_codes.items()
                if current_time - vc.get("created_at", 0) > expire_seconds
            ]
            for code in expired_codes:
                vc = self.session_manager.get_verify_code(code)
                self.session_manager.delete_verify_code(code)
                if vc and vc.get("session_id"):
                    self.session_manager.delete_session(vc["session_id"])

            # 区分 access_token 和 refresh_token 的过期时间
            # access_token: 3600 秒（1 小时）
            # refresh_token: 30 天（2592000 秒）
            expired_access_tokens = []
            expired_refresh_tokens = []
            for token, data in self.access_tokens.items():
                token_type = data.get("type", "access_token")
                created_at = data.get("created_at", current_time)
                if token_type == "refresh_token":
                    # refresh_token 有效期 30 天
                    if current_time - created_at > 2592000:
                        expired_refresh_tokens.append(token)
                else:
                    # access_token 有效期 1 小时
                    if current_time - created_at > 3600:
                        expired_access_tokens.append(token)

            for token in expired_access_tokens:
                self.session_manager.delete_access_token(token)
            for token in expired_refresh_tokens:
                self.session_manager.delete_access_token(token)

        if expired_codes or expired_access_tokens or expired_refresh_tokens:
            logger.debug(
                f"清理过期数据: {len(expired_codes)} 个验证码, {len(expired_access_tokens)} 个 access_token, {len(expired_refresh_tokens)} 个 refresh_token"
            )

        # 保存清理后的数据
        await self.session_manager.save_all()


class RateLimiter:
    """速率限制器

    用于限制登录尝试频率，防止暴力破解攻击。
    支持基于 IP 和用户的速率限制。
    """

    def __init__(
        self,
        max_attempts: int = 5,
        lockout_duration: int = 900,
        window_size: int = 300,
        on_rate_limit_triggered: callable = None,
    ):
        """初始化速率限制器

        Args:
            max_attempts: 最大尝试次数（默认5次）
            lockout_duration: 锁定时间（秒，默认15分钟）
            window_size: 时间窗口大小（秒，默认5分钟）
            on_rate_limit_triggered: 速率限制触发时的回调函数
        """
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.window_size = window_size
        self.on_rate_limit_triggered = on_rate_limit_triggered
        self._attempts: dict[str, list] = {}  # key -> [timestamp1, timestamp2, ...]
        self._lockouts: dict[str, float] = {}  # key -> lockout_end_time
        self._lock = asyncio.Lock()

    def _get_key(self, identifier: str, ip: str = "") -> str:
        """生成唯一标识键"""
        if ip:
            return f"{identifier}:{ip}"
        return identifier

    async def check_rate_limit(self, identifier: str, ip: str = "") -> tuple[bool, str]:
        """检查是否超出速率限制（已废弃，使用 check_and_record_limit 代替）

        Args:
            identifier: 用户标识（如用户名）
            ip: IP地址

        Returns:
            (是否允许, 错误信息)
        """
        async with self._lock:
            key = self._get_key(identifier, ip)
            current_time = time.time()

            # 检查是否处于锁定状态
            if key in self._lockouts:
                lockout_end = self._lockouts[key]
                if current_time < lockout_end:
                    remaining = int(lockout_end - current_time)
                    return False, f"登录尝试次数过多，请 {remaining // 60} 分钟后再试"
                else:
                    # 锁定已过期，清除记录
                    del self._lockouts[key]
                    if key in self._attempts:
                        del self._attempts[key]

            # 清理过期的尝试记录
            if key in self._attempts:
                self._attempts[key] = [
                    t
                    for t in self._attempts[key]
                    if current_time - t < self.window_size
                ]
            else:
                self._attempts[key] = []

            # 检查尝试次数
            if len(self._attempts[key]) >= self.max_attempts:
                # 触发锁定
                self._lockouts[key] = current_time + self.lockout_duration

                # 调用回调函数记录告警
                if self.on_rate_limit_triggered:
                    try:
                        await self.on_rate_limit_triggered(
                            identifier, ip, len(self._attempts[key])
                        )
                    except Exception as e:
                        logger.error(f"速率限制告警回调失败: {e}")

                return (
                    False,
                    f"登录尝试次数过多，已锁定 {self.lockout_duration // 60} 分钟",
                )

            return True, ""

    async def record_attempt(self, identifier: str, ip: str = ""):
        """记录一次尝试（已废弃，使用 check_and_record_limit 代替）"""
        async with self._lock:
            key = self._get_key(identifier, ip)
            if key not in self._attempts:
                self._attempts[key] = []
            self._attempts[key].append(time.time())

    async def check_and_record_limit(
        self, identifier: str, ip: str = ""
    ) -> tuple[bool, str]:
        """原子性地检查速率限制并记录尝试

        防止并发竞争窗口，确保检查和记录是原子操作。

        Args:
            identifier: 用户标识（如用户名）
            ip: IP地址

        Returns:
            (是否允许, 错误信息)
        """
        async with self._lock:
            key = self._get_key(identifier, ip)
            current_time = time.time()

            # 检查是否处于锁定状态
            if key in self._lockouts:
                lockout_end = self._lockouts[key]
                if current_time < lockout_end:
                    remaining = int(lockout_end - current_time)
                    return False, f"登录尝试次数过多，请 {remaining // 60} 分钟后再试"
                else:
                    # 锁定已过期，清除记录
                    del self._lockouts[key]
                    if key in self._attempts:
                        del self._attempts[key]

            # 清理过期的尝试记录
            if key in self._attempts:
                self._attempts[key] = [
                    t
                    for t in self._attempts[key]
                    if current_time - t < self.window_size
                ]
            else:
                self._attempts[key] = []

            # 检查尝试次数
            if len(self._attempts[key]) >= self.max_attempts:
                # 触发锁定
                self._lockouts[key] = current_time + self.lockout_duration

                # 调用回调函数记录告警
                if self.on_rate_limit_triggered:
                    try:
                        await self.on_rate_limit_triggered(
                            identifier, ip, len(self._attempts[key])
                        )
                    except Exception as e:
                        logger.error(f"速率限制告警回调失败: {e}")

                return (
                    False,
                    f"登录尝试次数过多，已锁定 {self.lockout_duration // 60} 分钟",
                )

            # 记录本次尝试（原子操作）
            self._attempts[key].append(current_time)
            return True, ""

    async def reset_attempts(self, identifier: str, ip: str = ""):
        """重置尝试记录（登录成功时调用）"""
        async with self._lock:
            key = self._get_key(identifier, ip)
            if key in self._attempts:
                del self._attempts[key]
            if key in self._lockouts:
                del self._lockouts[key]

    def get_attempts_info(self, identifier: str, ip: str = "") -> dict:
        """获取尝试信息（用于调试）"""
        key = self._get_key(identifier, ip)
        current_time = time.time()
        attempts = self._attempts.get(key, [])
        valid_attempts = [t for t in attempts if current_time - t < self.window_size]

        return {
            "attempts_count": len(valid_attempts),
            "max_attempts": self.max_attempts,
            "is_locked": key in self._lockouts
            and current_time < self._lockouts.get(key, 0),
            "lockout_remaining": max(0, int(self._lockouts.get(key, 0) - current_time))
            if key in self._lockouts
            else 0,
        }


class WebHandler:
    """Web 请求处理器

    处理所有 HTTP 请求，包括：
    - OIDC 端点（发现文档、授权、令牌、用户信息）
    - Web 管理后台页面和 API
    - 验证码输入页面
    """

    # Session 过期时间（24小时）
    SESSION_EXPIRE_SECONDS = 86400

    def __init__(
        self,
        plugin,
        oidc_server: OIDCServer,
        config_manager: ConfigManager,
        client_manager: ClientManager,
        audit_log_manager: AuditLogManager,
    ):
        self.plugin = plugin
        self.oidc_server = oidc_server
        self.config_manager = config_manager
        self.client_manager = client_manager
        self.audit_log_manager = audit_log_manager
        self.sessions: dict[str, dict] = {}
        self._lock = asyncio.Lock()  # 用于保护会话操作

        # 速率限制告警回调函数
        async def on_rate_limit_triggered(identifier: str, ip: str, attempts: int):
            self.audit_log_manager.log(
                action="RATE_LIMIT_TRIGGERED",
                details=f"触发速率限制: {attempts} 次失败尝试",
                user=identifier,
                ip=ip,
            )
            logger.warning(
                f"速率限制触发: 用户={identifier}, IP={ip}, 尝试次数={attempts}"
            )

        # 初始化速率限制器
        self.rate_limiter = RateLimiter(
            max_attempts=5,
            lockout_duration=900,  # 15分钟
            window_size=300,  # 5分钟
            on_rate_limit_triggered=on_rate_limit_triggered,
        )

        # 验证码验证速率限制器（更严格的限制）
        async def on_verify_rate_limit_triggered(
            identifier: str, ip: str, attempts: int
        ):
            self.audit_log_manager.log(
                action="VERIFY_RATE_LIMITED",
                details=f"验证码验证速率限制触发: {attempts} 次尝试",
                user=identifier,
                ip=ip,
            )
            logger.warning(f"验证码验证速率限制触发: IP={ip}, 尝试次数={attempts}")

        self.verify_rate_limiter = RateLimiter(
            max_attempts=10,  # 每个IP最多10次尝试
            lockout_duration=300,  # 锁定5分钟
            window_size=60,  # 1分钟窗口
            on_rate_limit_triggered=on_verify_rate_limit_triggered,
        )

        # 启动后台清理任务
        self._cleanup_task: asyncio.Task | None = None
        self._start_cleanup_task()

    def _start_cleanup_task(self):
        """启动后台清理任务"""

        async def cleanup_expired_sessions():
            while True:
                try:
                    await asyncio.sleep(3600)  # 每小时清理一次
                    await self._cleanup_expired_sessions()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"清理过期 session 时出错: {e}")

        self._cleanup_task = asyncio.create_task(cleanup_expired_sessions())

    async def _cleanup_expired_sessions(self):
        """清理过期的 session

        使用锁保护，防止并发竞争条件。
        """
        async with self._lock:
            current_time = time.time()
            expired_tokens = []
            for token, session in self.sessions.items():
                created_at = session.get("created_at", 0)
                if current_time - created_at > self.SESSION_EXPIRE_SECONDS:
                    expired_tokens.append(token)

            for token in expired_tokens:
                self.sessions.pop(token, None)

            if expired_tokens:
                logger.info(f"清理了 {len(expired_tokens)} 个过期 session")

    async def stop_cleanup_task(self):
        """停止后台清理任务"""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _validate_session(self, token: str) -> bool:
        """验证 session 是否有效（未过期）

        使用锁保护，防止并发竞争条件。
        """
        async with self._lock:
            session = self.sessions.get(token)
            if not session:
                return False
            created_at = session.get("created_at", 0)
            if time.time() - created_at > self.SESSION_EXPIRE_SECONDS:
                # Session 已过期，删除
                self.sessions.pop(token, None)  # 使用 pop 避免 KeyError
                logger.info(f"Session 已过期并删除: {token[:10]}...")
                return False
            return True

    def _get_config(self, key: str, default=None):
        return self.plugin._get_config(key, default)

    def _get_web_config(self, key: str, default=None):
        return self.config_manager.get(key, default)

    def _is_password_hashed(self, password: str) -> bool:
        """检查密码是否已哈希

        支持检测两种哈希格式：
        1. PBKDF2 格式: pbkdf2_sha256$iterations$salt$hash
        2. 旧 SHA-256 格式: salt:hash

        Args:
            password: 配置中的密码值

        Returns:
            是否已哈希
        """
        return password.startswith("pbkdf2_sha256$") or ":" in password

    def _check_password_default(self) -> bool:
        """检查是否使用默认密码

        检查用户名和密码是否都是默认值。
        注意：如果密码已哈希，此方法会返回 False。
        """
        username = self._get_config("web_username", "yeoidc")
        password = self._get_config("web_password", "yeoidc")
        # 如果密码已哈希，则不是默认密码
        if self._is_password_hashed(password):
            return False
        return username == "yeoidc" and password == "yeoidc"

    def _verify_login(self, username: str, password: str) -> bool:
        """验证登录凭据

        支持明文密码和哈希密码的验证。
        自动识别密码格式（PBKDF2 或明文）。
        """
        config_username = self._get_config("web_username", "yeoidc")
        config_password = self._get_config("web_password", "yeoidc")

        if username != config_username:
            return False

        # 检查密码是否已哈希
        if self._is_password_hashed(config_password):
            return verify_password(password, config_password)
        else:
            # 明文密码（向后兼容）
            return password == config_password

    def _generate_session_token(self) -> str:
        return secrets.token_urlsafe(32)

    def _get_allowed_origins(self) -> list[str]:
        """获取允许的 CORS 域名列表"""
        origins = []
        for client_data in self.client_manager.get_all_clients().values():
            # 优先使用 redirect_urls（新字段），兼容 redirect_url（旧字段）
            redirect_urls = client_data.get("redirect_urls", [])
            if not redirect_urls:
                # 兼容旧数据，使用单个 redirect_url
                redirect_url = client_data.get("redirect_url", "")
                if redirect_url:
                    redirect_urls = [redirect_url]

            for redirect_url in redirect_urls:
                if redirect_url:
                    try:
                        parsed = urlparse(redirect_url)
                        origin = f"{parsed.scheme}://{parsed.netloc}"
                        if origin not in origins:
                            origins.append(origin)
                    except Exception:
                        pass
        return origins

    def _set_cors_headers(self, response: web.Response, request: web.Request):
        """设置 CORS 响应头，限制为已注册客户端的域名"""
        origin = request.headers.get("Origin", "")
        allowed_origins = self._get_allowed_origins()

        # 对于 OIDC 端点，允许已注册的客户端域名
        # 对于管理后台 API，允许当前请求的域名（如果来自管理后台）
        if origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
        else:
            # 对于 .well-known 端点，允许所有域名（这是 OIDC 规范要求的）
            path = request.path.strip("/")
            if path.startswith(".well-known") or path == "authorize":
                response.headers["Access-Control-Allow-Origin"] = "*"
            elif origin:
                # 记录未授权的 CORS 请求
                logger.warning(f"CORS 请求被拒绝: origin={origin}, path={path}")

        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Vary"] = "Origin"

        # 添加安全相关的 HTTP 头部
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # 添加 Content-Security-Policy 头部，防止 XSS 攻击
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.jsdelivr.net; "
            "font-src fonts.gstatic.com cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

    async def handle_root(self, request: web.Request) -> web.Response:
        """根路由处理器

        处理所有请求路由，分发到对应的处理器。
        包含全局异常捕获，防止插件因单个请求错误而崩溃。
        """
        try:
            if request.method == "OPTIONS":
                response = web.Response()
                self._set_cors_headers(response, request)
                return response

            secure_path = self._get_config("secure_path", "chuyeoidc")
            path = request.path.strip("/")

            # 路由映射表
            route_handlers = {
                secure_path: self.handle_admin,
                f"{secure_path}/login": self.handle_login,
                f"{secure_path}/api/login": self.handle_api_login,
                f"{secure_path}/api/logout": self.handle_api_logout,
                f"{secure_path}/api/config": self.handle_api_config,
                f"{secure_path}/api/config/save": self.handle_api_config_save,
                f"{secure_path}/api/sessions": self.handle_api_sessions,
                f"{secure_path}/api/clients": self.handle_api_clients,
                f"{secure_path}/api/check_password": self.handle_api_check_password,
                f"{secure_path}/api/clients/add": self.handle_api_clients_add,
                f"{secure_path}/api/clients/update": self.handle_api_clients_update,
                f"{secure_path}/api/clients/delete": self.handle_api_clients_delete,
                f"{secure_path}/api/logs": self.handle_api_logs,
                f"{secure_path}/api/logs/clear": self.handle_api_logs_clear,
                "authorize": self.handle_authorize,
                "token": self.handle_token,
                "userinfo": self.handle_userinfo,
                ".well-known/openid-configuration": self.handle_discovery,
                ".well-known/jwks.json": self.handle_jwks,
                "verify": self.handle_verify_page,
                "api/verify": self.handle_api_verify,
                "api/session/status": self.handle_api_session_status,
            }

            handler = route_handlers.get(path)
            if handler:
                return await handler(request)
            else:
                return web.Response(text="Not Found", status=404)

        except Exception as e:
            logger.exception(f"请求处理错误: path={request.path}, error={e}")
            return web.json_response(
                {"error": "internal_server_error", "message": "服务器内部错误"},
                status=500,
            )

    async def handle_admin(self, request: web.Request) -> web.Response:
        is_default_password = self._check_password_default()
        theme_color = self._get_web_config("theme_color", "#50b6fe")
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
        theme_color = self._get_web_config("theme_color", "#50b6fe")
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
            username = data.get("username", "").strip()
            password = data.get("password", "")
            ip = request.remote or ""

            # 原子性地检查速率限制并记录尝试
            allowed, error_msg = await self.rate_limiter.check_and_record_limit(
                username, ip
            )
            if not allowed:
                self.audit_log_manager.log(
                    action="LOGIN_RATE_LIMITED",
                    details=error_msg,
                    user=username,
                    ip=ip,
                )
                return web.json_response(
                    {"success": False, "message": error_msg},
                    status=429,  # Too Many Requests
                )

            if self._check_password_default():
                self.audit_log_manager.log(
                    action="LOGIN_FAILED",
                    details="尝试使用默认密码登录",
                    user=username,
                    ip=ip,
                )
                return web.json_response(
                    {
                        "success": False,
                        "message": "请先在插件管理中修改默认密码后再登录",
                        "is_default_password": True,
                    },
                    status=401,
                )

            if self._verify_login(username, password):
                # 登录成功，重置尝试记录
                await self.rate_limiter.reset_attempts(username, ip)
                token = self._generate_session_token()
                self.sessions[token] = {"username": username, "created_at": time.time()}
                self.audit_log_manager.log(
                    action="LOGIN",
                    details="管理后台登录成功",
                    user=username,
                    ip=ip,
                )
                return web.json_response({"success": True, "token": token})
            else:
                # 登录失败，获取剩余尝试次数
                attempts_info = self.rate_limiter.get_attempts_info(username, ip)
                remaining = max(
                    0, attempts_info["max_attempts"] - attempts_info["attempts_count"]
                )

                self.audit_log_manager.log(
                    action="LOGIN_FAILED",
                    details=f"用户名或密码错误，剩余尝试次数: {remaining}",
                    user=username,
                    ip=ip,
                )
                error_message = "用户名或密码错误"
                if remaining > 0:
                    error_message += f"，还剩 {remaining} 次尝试机会"
                return web.json_response(
                    {"success": False, "message": error_message}, status=401
                )
        except Exception as e:
            logger.error(f"登录处理错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_logout(self, request: web.Request) -> web.Response:
        """处理登出请求

        安全说明：
        - 验证 token 有效性后才允许登出
        - 无效的 token 返回 401 错误
        - 使用锁保护和 pop 方法避免竞态条件
        """
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )
        # 使用锁保护和 pop 方法避免竞态条件
        async with self._lock:
            self.sessions.pop(token, None)
        return web.json_response({"success": True})

    async def handle_api_check_password(self, request: web.Request) -> web.Response:
        """检查是否使用默认密码

        用于前端显示警告信息，提示用户修改默认密码。
        """
        try:
            return web.json_response(
                {"success": True, "is_default": self._check_password_default()}
            )
        except Exception as e:
            logger.error(f"检查密码状态错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_config(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
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
            "poll_interval": self._get_web_config("poll_interval", 1),
            "theme_color": self._get_web_config("theme_color", "#50b6fe"),
            "icon_url": self._get_web_config("icon_url", ""),
            "favicon_url": self._get_web_config("favicon_url", ""),
            "jwt_secret": self._get_web_config("jwt_secret", ""),
        }
        return web.json_response({"success": True, "config": config_data})

    async def handle_api_config_save(self, request: web.Request) -> web.Response:
        """保存配置

        对输入数据进行验证，确保配置值合法。
        """
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            data = await request.json()

            # 验证数值范围
            if "code_expire_seconds" in data:
                value = data["code_expire_seconds"]
                if not isinstance(value, int) or value < 60 or value > 3600:
                    return web.json_response(
                        {
                            "success": False,
                            "message": "验证码有效期必须在 60-3600 秒之间",
                        },
                        status=400,
                    )

            if "code_length" in data:
                value = data["code_length"]
                if not isinstance(value, int) or value < 4 or value > 10:
                    return web.json_response(
                        {"success": False, "message": "验证码长度必须在 4-10 位之间"},
                        status=400,
                    )

            if "poll_interval" in data:
                value = data["poll_interval"]
                if not isinstance(value, int) or value < 1 or value > 30:
                    return web.json_response(
                        {"success": False, "message": "轮询间隔必须在 1-30 秒之间"},
                        status=400,
                    )

            # 验证群号格式
            if "verify_group_id" in data:
                if not validate_group_id(data["verify_group_id"]):
                    return web.json_response(
                        {"success": False, "message": "群号格式无效，只允许数字和逗号"},
                        status=400,
                    )

            # 验证 URL 格式
            if "icon_url" in data and not validate_url(data["icon_url"]):
                return web.json_response(
                    {"success": False, "message": "图标 URL 格式无效"},
                    status=400,
                )

            if "favicon_url" in data and not validate_url(data["favicon_url"]):
                return web.json_response(
                    {"success": False, "message": "Favicon URL 格式无效"},
                    status=400,
                )

            # 验证颜色格式
            if "theme_color" in data and not validate_color(data["theme_color"]):
                return web.json_response(
                    {
                        "success": False,
                        "message": "主题颜色格式无效，必须是有效的 CSS 颜色值（如 #50b6fe）",
                    },
                    status=400,
                )

            allowed_keys = [
                "enable_group_verify",
                "enable_private_verify",
                "verify_group_id",
                "code_expire_seconds",
                "code_length",
                "poll_interval",
                "theme_color",
                "icon_url",
                "favicon_url",
                "jwt_secret",
            ]

            update_data = {}
            for key in allowed_keys:
                if key in data:
                    update_data[key] = data[key]

            if self.config_manager.update(update_data):
                # 记录配置更新审计日志
                username = self.sessions.get(token, {}).get("username", "unknown")
                self.audit_log_manager.log(
                    action="CONFIG_UPDATE",
                    details=f"更新配置: {list(update_data.keys())}",
                    user=username,
                    ip=request.remote or "",
                )
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
        """获取所有 OIDC 会话列表

        返回当前活跃的认证会话信息，用于管理后台监控。
        """
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            sessions = []
            for session_id, session in self.oidc_server.sessions.items():
                sessions.append(
                    {
                        "session_id": session_id,
                        "code": session.get("code", ""),
                        "state": session.get("state", ""),
                        "verified": session.get("verified", False),
                        "verified_user_id": session.get("verified_user_id", ""),
                        "created_at": session.get("created_at", 0),
                    }
                )

            return web.json_response({"success": True, "sessions": sessions})
        except Exception as e:
            logger.error(f"获取会话列表错误: {e}")
            return web.json_response(
                {"success": False, "message": "获取会话列表失败"}, status=500
            )

    async def handle_api_clients(self, request: web.Request) -> web.Response:
        """获取所有 OIDC 客户端列表

        返回所有注册的 OIDC 客户端信息，用于管理后台管理。
        兼容旧数据格式（单 URL 转为列表）。
        """
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            clients = []
            for client_id, client_data in self.client_manager.get_all_clients().items():
                # 兼容旧数据格式
                home_urls = client_data.get("home_urls", [])
                redirect_urls = client_data.get("redirect_urls", [])
                if not home_urls and client_data.get("home_url"):
                    home_urls = [client_data.get("home_url")]
                if not redirect_urls and client_data.get("redirect_url"):
                    redirect_urls = [client_data.get("redirect_url")]

                clients.append(
                    {
                        "client_id": client_id,
                        "client_secret": "********",  # 隐藏敏感信息，不在列表中显示
                        "name": client_data.get("name", client_id),
                        "home_urls": home_urls,
                        "redirect_urls": redirect_urls,
                        "created_at": client_data.get("created_at", 0),
                    }
                )

            return web.json_response({"success": True, "clients": clients})
        except Exception as e:
            logger.error(f"获取客户端列表错误: {e}")
            return web.json_response(
                {"success": False, "message": "获取客户端列表失败"}, status=500
            )

    async def handle_api_clients_add(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            data = await request.json()
            client_id = data.get("client_id", "")
            client_secret = data.get("client_secret", "")
            name = data.get("name", "")
            home_urls = data.get("home_urls", [])
            redirect_urls = data.get("redirect_urls", [])

            if not client_id:
                client_id = self.client_manager.generate_client_id()
            if not client_secret:
                client_secret = self.client_manager.generate_client_secret()
            if not name:
                name = self.client_manager.generate_client_name()

            # 兼容旧数据格式
            if not home_urls and data.get("home_url"):
                home_urls = [data.get("home_url")]
            if not redirect_urls and data.get("redirect_url"):
                redirect_urls = [data.get("redirect_url")]

            if self.client_manager.add_client(
                client_id, client_secret, name, home_urls, redirect_urls
            ):
                # 记录客户端创建审计日志
                username = self.sessions.get(token, {}).get("username", "unknown")
                self.audit_log_manager.log(
                    action="CLIENT_ADD",
                    details=f"创建客户端: {name} ({client_id})",
                    user=username,
                    ip=request.remote or "",
                )
                return web.json_response(
                    {
                        "success": True,
                        "message": "客户端创建成功",
                        "client": {
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "name": name,
                            "home_urls": home_urls,
                            "redirect_urls": redirect_urls,
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

    async def handle_api_clients_update(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            data = await request.json()
            client_id = data.get("client_id", "")
            client_secret = data.get("client_secret", "")
            name = data.get("name", "")
            home_urls = data.get("home_urls", [])
            redirect_urls = data.get("redirect_urls", [])

            if not client_id:
                return web.json_response(
                    {"success": False, "message": "缺少 client_id"}, status=400
                )

            # 兼容旧数据格式
            if not home_urls and data.get("home_url"):
                home_urls = [data.get("home_url")]
            if not redirect_urls and data.get("redirect_url"):
                redirect_urls = [data.get("redirect_url")]

            if self.client_manager.update_client(
                client_id, client_secret, name, home_urls, redirect_urls
            ):
                # 记录客户端更新审计日志
                username = self.sessions.get(token, {}).get("username", "unknown")
                self.audit_log_manager.log(
                    action="CLIENT_UPDATE",
                    details=f"更新客户端: {name} ({client_id})",
                    user=username,
                    ip=request.remote or "",
                )
                return web.json_response(
                    {
                        "success": True,
                        "message": "客户端更新成功",
                        "client": {
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "name": name,
                            "home_urls": home_urls,
                            "redirect_urls": redirect_urls,
                        },
                    }
                )
            else:
                return web.json_response(
                    {"success": False, "message": "客户端不存在"}, status=404
                )
        except Exception as e:
            logger.error(f"更新客户端错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_clients_delete(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            data = await request.json()
            client_id = data.get("client_id", "")

            if not client_id:
                return web.json_response(
                    {"success": False, "message": "缺少 client_id"}, status=400
                )

            if self.client_manager.delete_client(client_id):
                # 记录客户端删除审计日志
                username = self.sessions.get(token, {}).get("username", "unknown")
                self.audit_log_manager.log(
                    action="CLIENT_DELETE",
                    details=f"删除客户端: {client_id}",
                    user=username,
                    ip=request.remote or "",
                )
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

    async def handle_api_logs(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            limit = min(
                int(request.query.get("limit", 100)), 1000
            )  # 限制最大1000，防止DoS
            offset = max(0, int(request.query.get("offset", 0)))  # 确保非负
            action_filter = request.query.get("action", None)

            logs = self.audit_log_manager.get_logs(limit, offset, action_filter)
            total = self.audit_log_manager.get_logs_count(action_filter)

            return web.json_response(
                {
                    "success": True,
                    "logs": logs,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                }
            )
        except Exception as e:
            logger.error(f"获取审计日志错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_logs_clear(self, request: web.Request) -> web.Response:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not await self._validate_session(token):
            return web.json_response(
                {"success": False, "message": "未授权或会话已过期"}, status=401
            )

        try:
            self.audit_log_manager.clear_logs()
            # 记录清空日志操作
            username = self.sessions.get(token, {}).get("username", "unknown")
            self.audit_log_manager.log(
                action="CLEAR_LOGS",
                details="清空审计日志",
                user=username,
                ip=request.remote or "",
            )
            return web.json_response({"success": True, "message": "日志已清空"})
        except Exception as e:
            logger.error(f"清空审计日志错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_authorize(self, request: web.Request) -> web.Response:
        """处理 OIDC 授权请求

        安全说明：
        - 添加了速率限制，防止滥用生成大量会话
        - 验证 redirect_uri 是否与客户端注册的一致
        """
        # 速率限制检查
        ip = request.remote or ""
        allowed, error_msg = await self.rate_limiter.check_and_record_limit(
            f"authorize:{ip}", ip
        )
        if not allowed:
            logger.warning(f"授权端点速率限制触发: IP={ip}")
            return web.json_response(
                {"error": "rate_limit_exceeded", "error_description": error_msg},
                status=429,
            )

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

        # 校验 redirect_uri 是否与客户端注册的 redirect_url 匹配
        # 对收到的 redirect_uri 进行解码，以支持 URL 编码的地址
        from urllib.parse import unquote

        decoded_redirect_uri = unquote(redirect_uri)

        # 使用新的 verify_redirect_uri 方法验证
        if not self.client_manager.verify_redirect_uri(client_id, decoded_redirect_uri):
            logger.warning(
                f"redirect_uri 不匹配: client_id={client_id}, uri={decoded_redirect_uri}"
            )
            return web.json_response(
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri does not match registered redirect_url",
                },
                status=400,
            )

        # 使用解码后的 redirect_uri 创建会话，确保与 token 端点比较时一致
        session_id, verify_code, auth_code = await self.oidc_server.create_auth_session(
            decoded_redirect_uri, state, client_id
        )

        html = self._render_verify_page(
            verify_code, auth_code, session_id, redirect_uri, state, scope, client
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

        logger.info(f"Token请求: grant_type={grant_type}, client_id={client_id}")

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

        if grant_type == "authorization_code":
            # 使用授权码换取 token
            redirect_uri = data.get("redirect_uri", "")

            if not client_id:
                return web.json_response(
                    {
                        "error": "invalid_client",
                        "error_description": "missing client_id",
                    },
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

            token_data = await self.oidc_server.exchange_code(
                code, client_id, redirect_uri
            )

            if not token_data:
                return web.json_response({"error": "invalid_grant"}, status=400)

            # 记录授权审计日志
            self.audit_log_manager.log(
                action="TOKEN_EXCHANGE",
                details=f"授权码换取Token: client_id={client_id}",
                user="",
                ip=request.remote or "",
            )

            response = web.json_response(token_data)
            self._set_cors_headers(response, request)
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"
            return response

        elif grant_type == "refresh_token":
            # 使用 refresh_token 换取新的 token
            refresh_token = data.get("refresh_token", "")

            if not client_id:
                return web.json_response(
                    {
                        "error": "invalid_client",
                        "error_description": "missing client_id",
                    },
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

            token_data = await self.oidc_server.exchange_refresh_token(
                refresh_token, client_id
            )

            if not token_data:
                return web.json_response(
                    {
                        "error": "invalid_grant",
                        "error_description": "invalid refresh_token",
                    },
                    status=400,
                )

            # 记录刷新 token 审计日志
            self.audit_log_manager.log(
                action="TOKEN_REFRESH",
                details=f"刷新Token: client_id={client_id}",
                user="",
                ip=request.remote or "",
            )

            response = web.json_response(token_data)
            self._set_cors_headers(response, request)
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"
            return response

        else:
            return web.json_response({"error": "unsupported_grant_type"}, status=400)

    async def handle_userinfo(self, request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning("Userinfo: 缺少Bearer token")
            return web.json_response({"error": "invalid_token"}, status=401)

        token = auth_header[7:]
        user_data = await self.oidc_server.get_user_info(token)

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

        response = web.json_response(userinfo_response)
        self._set_cors_headers(response, request)
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"
        return response

    async def handle_discovery(self, request: web.Request) -> web.Response:
        host = request.host
        # 验证 Host header 是否合法，防止 Host Header 污染攻击
        if not validate_host_header(host):
            return web.json_response(
                {
                    "error": "invalid_request",
                    "error_description": "Invalid host header",
                },
                status=400,
            )

        # 使用配置的 public_url 作为 issuer，确保安全性
        # 不再从请求中动态获取，防止 Host Header 污染攻击
        configured_issuer = self.oidc_server.get_issuer()
        if not configured_issuer:
            # 强制要求配置 public_url
            logger.error("未配置 public_url，无法提供 OIDC 发现文档")
            return web.json_response(
                {
                    "error": "configuration_error",
                    "error_description": "public_url not configured",
                },
                status=500,
            )
        base_url = configured_issuer

        discovery = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "userinfo_endpoint": f"{base_url}/userinfo",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            # 注意：PKCE 未实现，不声明 code_challenge_methods_supported
            # 避免误导客户端启用 PKCE 而实际无防护
            "claims_supported": [
                "sub",
                "name",
                "nickname",
                "email",
                "iss",
                "aud",
                "exp",
                "iat",
            ],
        }

        response = web.json_response(discovery)
        self._set_cors_headers(response, request)
        return response

    async def handle_jwks(self, request: web.Request) -> web.Response:
        """JWKS 端点 - 提供 JWT 签名公钥

        返回 RSA 公钥的 JWKS 格式，供客户端验证 JWT 签名。
        使用 RS256 非对称加密算法，私钥签名，公钥验证。
        支持多密钥（用于密钥轮换）。
        """
        jwks = {"keys": self.oidc_server._get_jwks_keys()}

        response = web.json_response(jwks)
        self._set_cors_headers(response, request)
        return response

    async def handle_verify_page(self, request: web.Request) -> web.Response:
        code = request.query.get("code", "")
        session_id = request.query.get("session_id", "")

        html = self._render_verify_input_page(code, session_id)
        return web.Response(text=html, content_type="text/html", charset="utf-8")

    async def handle_api_verify(self, request: web.Request) -> web.Response:
        """验证码验证接口（仅用于检查验证码状态，不绑定用户身份）

        安全说明：
        - 此接口仅检查验证码是否有效，不绑定 user_id
        - user_id 只能通过 QQ 消息（可信通道）绑定
        - 防止攻击者通过自填 user_id 伪造身份
        - 添加速率限制防止暴力破解
        """
        try:
            ip = request.remote or ""

            # 检查速率限制
            allowed, error_msg = await self.verify_rate_limiter.check_and_record_limit(
                "verify_api", ip
            )
            if not allowed:
                return web.json_response(
                    {"success": False, "message": error_msg}, status=429
                )

            data = await request.json()
            code = data.get("code", "")

            if not code:
                return web.json_response(
                    {"success": False, "message": "验证码不能为空"}, status=400
                )

            # 检查验证码是否存在且有效
            verify_code_data = self.oidc_server.session_manager.get_verify_code(code)
            if not verify_code_data:
                return web.json_response(
                    {"success": False, "message": "验证码不存在"}, status=400
                )

            if verify_code_data.get("used", False):
                return web.json_response(
                    {"success": False, "message": "验证码已使用"}, status=400
                )

            expire_seconds = self._get_web_config("code_expire_seconds", 300)
            if time.time() - verify_code_data.get("created_at", 0) > expire_seconds:
                return web.json_response(
                    {"success": False, "message": "验证码已过期"}, status=400
                )

            session_id = verify_code_data.get("session_id")
            session_data = self.oidc_server.session_manager.get_session(session_id)

            if not session_data:
                return web.json_response(
                    {"success": False, "message": "会话不存在"}, status=400
                )

            if session_data.get("verified"):
                session = await self.oidc_server.get_session(session_id)
                if session:
                    parsed = urlparse(session.redirect_uri)
                    query_params = {}
                    if parsed.query:
                        for param in parsed.query.split("&"):
                            if "=" in param:
                                key, value = param.split("=", 1)
                                query_params[key] = value

                    query_params["code"] = session.auth_code
                    query_params["state"] = session.state

                    from urllib.parse import urlencode

                    new_query = urlencode(query_params)
                    redirect_url = (
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    )

                    return web.json_response(
                        {
                            "success": True,
                            "message": "验证成功",
                            "redirect_url": redirect_url,
                        }
                    )

            return web.json_response(
                {
                    "success": False,
                    "message": "验证码有效，请通过 QQ 群聊/私聊发送验证码完成身份验证",
                    "pending": True,
                }
            )
        except Exception as e:
            logger.error(f"验证处理错误: {e}")
            return web.json_response(
                {"success": False, "message": "服务器错误"}, status=500
            )

    async def handle_api_session_status(self, request: web.Request) -> web.Response:
        try:
            ip = request.remote or ""

            # 检查速率限制
            allowed, error_msg = await self.verify_rate_limiter.check_and_record_limit(
                "session_status", ip
            )
            if not allowed:
                return web.json_response(
                    {"success": False, "message": error_msg}, status=429
                )

            session_id = request.query.get("session_id", "")
            if not session_id:
                return web.json_response(
                    {"success": False, "message": "缺少session_id"}, status=400
                )

            session = await self.oidc_server.get_session(session_id)
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
        self, theme_color: str = "#50b6fe", icon_url: str = "", favicon_url: str = ""
    ) -> str:
        # 安全处理 icon_html，转义 URL
        icon_html = (
            f'<img src="{escape_html_attr(icon_url)}" class="w-16 h-16 object-cover rounded-lg" style="width: 64px; height: 64px; aspect-ratio: 1/1;" alt="icon">'
            if icon_url
            else """<svg xmlns="http://www.w3.org/2000/svg" style="width: 64px; height: 64px;" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>"""
        )

        # 使用外置模板，直接传递原始值
        return template_manager.render(
            "login",
            theme_color=theme_color,
            icon_html=icon_html,
            favicon_url=favicon_url,
        )

    def _render_admin_page(
        self,
        is_default_password: bool,
        theme_color: str = "#50b6fe",
        icon_url: str = "",
        favicon_url: str = "",
    ) -> str:
        warning_html = (
            """
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
            f'<img src="{escape_html_attr(icon_url)}" class="h-10 w-10 object-cover rounded-lg" alt="icon">'
            if icon_url
            else """<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>"""
        )

        # 对 theme_color 进行安全转义
        theme_color_js = escape_js_string(theme_color)
        theme_color_css = escape_css_value(theme_color)
        favicon_url_safe = escape_html_attr(favicon_url)

        return rf"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OIDC登录插件 - 管理后台</title>
    <link rel="icon" type="image/png" href="{favicon_url_safe}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{
                        primary: '{theme_color_js}',
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(12px); }}
        .tab-active {{ color: {theme_color_css}; border-bottom: 2px solid {theme_color_css}; }}
        .custom-scrollbar::-webkit-scrollbar {{ width: 6px; }}
        .custom-scrollbar::-webkit-scrollbar-track {{ background: transparent; }}
        .custom-scrollbar::-webkit-scrollbar-thumb {{ background: #e2e8f0; border-radius: 10px; }}
        .bg-primary {{ background-color: {theme_color_css}; }}
        .text-primary {{ color: {theme_color_css}; }}
        .border-primary {{ border-color: {theme_color_css}; }}
        .shadow-primary {{ box-shadow: 0 10px 15px -3px {theme_color_css}33; }}
        .hover\:bg-primary:hover {{ background-color: {theme_color_css}; }}
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
            <button class="tab px-4 py-3 text-sm font-bold text-slate-500 hover:text-primary transition-all flex items-center gap-2" data-tab="logs">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                审计日志
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
                                    <input type="color" id="themeColor" class="w-16 h-12 rounded-xl border border-slate-200 cursor-pointer" value="#50b6fe">
                                    <input type="text" id="themeColorText" class="flex-1 px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="#50b6fe">
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
                            <div>
                                <label class="block text-sm font-bold text-slate-700 mb-2">轮询间隔 (秒)</label>
                                <input type="number" id="pollInterval" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" min="1" max="30">
                                <p class="text-xs text-slate-500 mt-2">验证页面检查状态的时间间隔，范围 1-30 秒</p>
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
                        <div class="md:col-span-2">
                            <label class="block text-sm font-bold text-slate-700 mb-2">主页链接</label>
                            <div id="homeUrlsContainer" class="space-y-2">
                                <div class="flex items-center gap-2">
                                    <input type="text" class="home-url-input w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com">
                                </div>
                            </div>
                            <button onclick="addHomeUrlInput()" class="mt-2 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl text-sm font-bold transition-all flex items-center gap-2">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                                </svg>
                                添加主页链接
                            </button>
                        </div>
                        <div class="md:col-span-2">
                            <label class="block text-sm font-bold text-slate-700 mb-2">重定向 URL</label>
                            <div id="redirectUrlsContainer" class="space-y-2">
                                <div class="flex items-center gap-2">
                                    <input type="text" class="redirect-url-input w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com/oauth/callback">
                                </div>
                            </div>
                            <button onclick="addRedirectUrlInput()" class="mt-2 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl text-sm font-bold transition-all flex items-center gap-2">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                                </svg>
                                添加重定向 URL
                            </button>
                        </div>
                    </div>
                    <div class="mt-6 flex justify-end gap-3">
                        <button id="cancelEditBtn" onclick="resetClientForm()" class="hidden px-6 py-3 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-2xl font-bold transition-all active:scale-[0.98]">
                            取消编辑
                        </button>
                        <button id="addClientBtn" onclick="addClient()" class="px-6 py-3 bg-primary hover:opacity-90 text-white rounded-2xl font-bold shadow-lg shadow-primary/30 transition-all active:scale-[0.98] flex items-center gap-2">
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

        <div id="tab-logs" class="tab-content hidden">
            <div class="space-y-8">
                <div class="bg-white rounded-3xl p-8 shadow-sm border border-slate-100">
                    <div class="flex items-center justify-between mb-6">
                        <h2 class="text-lg font-bold flex items-center gap-2">
                            <span class="w-2 h-6 bg-primary rounded-full"></span>
                            审计日志
                        </h2>
                        <div class="flex items-center gap-3">
                            <select id="logFilter" class="px-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-sm font-medium focus:ring-2 focus:ring-primary/20 focus:border-primary outline-none">
                                <option value="">全部类型</option>
                                <option value="LOGIN">登录</option>
                                <option value="LOGOUT">登出</option>
                                <option value="CLIENT_ADD">添加客户端</option>
                                <option value="CLIENT_UPDATE">更新客户端</option>
                                <option value="CLIENT_DELETE">删除客户端</option>
                                <option value="CONFIG_UPDATE">配置更新</option>
                                <option value="AUTHORIZE">授权</option>
                                <option value="TOKEN_EXCHANGE">令牌交换</option>
                                <option value="CLEAR_LOGS">清空日志</option>
                            </select>
                            <button onclick="clearLogs()" class="px-4 py-2 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-xl text-sm font-bold transition-all flex items-center gap-2">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                </svg>
                                清空日志
                            </button>
                        </div>
                    </div>
                    <div class="bg-white rounded-3xl shadow-sm border border-slate-100 overflow-hidden">
                        <div class="overflow-x-auto custom-scrollbar max-h-[500px]">
                            <table class="w-full text-left border-collapse">
                                <thead class="sticky top-0 bg-white z-10">
                                    <tr class="bg-slate-50/50 border-b border-slate-100">
                                        <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">时间</th>
                                        <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">操作类型</th>
                                        <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">详情</th>
                                        <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">用户</th>
                                        <th class="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-wider">IP地址</th>
                                    </tr>
                                </thead>
                                <tbody id="logTable" class="divide-y divide-slate-100">
                                    <tr><td colspan="5" class="px-6 py-12 text-center text-slate-400 font-medium">加载中...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="flex items-center justify-between mt-6">
                        <span class="text-sm text-slate-500" id="logCount">共 0 条日志</span>
                        <div class="flex items-center gap-2">
                            <button onclick="changeLogPage(-1)" id="prevLogPage" class="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl text-sm font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                                上一页
                            </button>
                            <span class="text-sm text-slate-600 font-medium" id="logPageInfo">第 1 页</span>
                            <button onclick="changeLogPage(1)" id="nextLogPage" class="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-xl text-sm font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                                下一页
                            </button>
                        </div>
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
                document.getElementById('pollInterval').value = config.poll_interval || 1;
                document.getElementById('enableGroupVerify').checked = config.enable_group_verify !== false;
                document.getElementById('enablePrivateVerify').checked = config.enable_private_verify !== false;
                document.getElementById('verifyGroupId').value = config.verify_group_id || '';

                const themeColor = config.theme_color || '#50b6fe';
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
                poll_interval: parseInt(document.getElementById('pollInterval').value),
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
                    if (url.length <= maxLen) return escapeHtml(url);
                    return escapeHtml(url.substring(0, maxLen)) + '...';
                }}

                tbody.innerHTML = data.clients.map(c => {{
                    const safeName = escapeHtml(c.name);
                    const safeClientId = escapeHtml(c.client_id);
                    const safeClientSecret = escapeHtml(c.client_secret);
                    return `
                    <tr class="hover:bg-slate-50/50 transition-colors">
                        <td class="px-6 py-4 text-sm font-bold text-slate-700">
                            <div class="flex items-center gap-2">
                                ${{safeName}}
                                <button onclick="copyText('${{safeName}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <div class="flex items-center gap-2">
                                <code class="bg-indigo-50 text-indigo-600 px-2 py-1 rounded-lg font-bold text-sm">${{safeClientId}}</code>
                                <button onclick="copyText('${{safeClientId}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <div class="flex items-center gap-2">
                                <code class="bg-emerald-50 text-emerald-600 px-2 py-1 rounded-lg font-bold text-sm max-w-[80px] truncate" title="${{safeClientSecret}}">${{safeClientSecret}}</code>
                                <button onclick="copyText('${{safeClientSecret}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>
                        </td>
                        <td class="px-6 py-4 text-sm text-slate-600">
                            ${{c.home_urls && c.home_urls.length > 0 ? `
                                <div class="flex items-center gap-2">
                                    ${{c.home_urls.length === 1 ? `
                                        <span title="${{escapeHtml(c.home_urls[0])}}">${{truncateUrl(c.home_urls[0])}}</span>
                                        <button onclick="copyText('${{escapeHtml(c.home_urls[0])}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                            </svg>
                                        </button>
                                    ` : `<span class="px-2 py-1 bg-slate-100 rounded-lg text-xs font-bold">${{c.home_urls.length}} 个链接</span>`}}
                                </div>
                            ` : '<span class="text-slate-300">-</span>'}}
                        </td>
                        <td class="px-6 py-4 text-sm text-slate-600">
                            ${{c.redirect_urls && c.redirect_urls.length > 0 ? `
                                <div class="flex items-center gap-2">
                                    ${{c.redirect_urls.length === 1 ? `
                                        <span title="${{escapeHtml(c.redirect_urls[0])}}">${{truncateUrl(c.redirect_urls[0])}}</span>
                                        <button onclick="copyText('${{escapeHtml(c.redirect_urls[0])}}')" class="text-slate-400 hover:text-indigo-600 transition-colors" title="复制">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                            </svg>
                                        </button>
                                    ` : `<span class="px-2 py-1 bg-slate-100 rounded-lg text-xs font-bold">${{c.redirect_urls.length}} 个链接</span>`}}
                                </div>
                            ` : '<span class="text-slate-300">-</span>'}}
                        </td>
                        <td class="px-6 py-4 text-sm text-slate-400 font-medium">${{new Date(c.created_at * 1000).toLocaleString()}}</td>
                        <td class="px-6 py-4">
                            <div class="flex items-center gap-2">
                                <button onclick='editClient(${{JSON.stringify(c.client_id)}}, ${{JSON.stringify(c.name)}}, ${{JSON.stringify(c.client_secret)}}, ${{JSON.stringify(c.home_urls || [])}}, ${{JSON.stringify(c.redirect_urls || [])}})' class="px-3 py-1.5 bg-primary/10 text-primary hover:bg-primary/20 rounded-lg text-xs font-bold transition-all">编辑</button>
                                <button onclick="deleteClient(${{JSON.stringify(c.client_id)}})" class="px-3 py-1.5 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-lg text-xs font-bold transition-all">删除</button>
                            </div>
                        </td>
                    </tr>
                `;}}).join('');
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

        // 编辑客户端相关函数
        let editingClientId = null;

        function addHomeUrlInput(value = '') {{
            const container = document.getElementById('homeUrlsContainer');
            const div = document.createElement('div');
            div.className = 'flex items-center gap-2';
            div.innerHTML = `
                <input type="text" class="home-url-input w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com" value="${{value}}">
                <button onclick="this.parentElement.remove()" class="px-3 py-3 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-xl transition-all" title="删除">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            `;
            container.appendChild(div);
        }}

        function addRedirectUrlInput(value = '') {{
            const container = document.getElementById('redirectUrlsContainer');
            const div = document.createElement('div');
            div.className = 'flex items-center gap-2';
            div.innerHTML = `
                <input type="text" class="redirect-url-input w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com/oauth/callback" value="${{value}}">
                <button onclick="this.parentElement.remove()" class="px-3 py-3 bg-rose-50 text-rose-600 hover:bg-rose-100 rounded-xl transition-all" title="删除">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            `;
            container.appendChild(div);
        }}

        function getHomeUrls() {{
            const inputs = document.querySelectorAll('#homeUrlsContainer .home-url-input');
            return Array.from(inputs).map(input => input.value.trim()).filter(url => url);
        }}

        function getRedirectUrls() {{
            const inputs = document.querySelectorAll('#redirectUrlsContainer .redirect-url-input');
            return Array.from(inputs).map(input => input.value.trim()).filter(url => url);
        }}

        function resetClientForm() {{
            editingClientId = null;
            document.getElementById('newClientName').value = '';
            document.getElementById('newClientId').value = '';
            document.getElementById('newClientSecret').value = '';
            document.getElementById('homeUrlsContainer').innerHTML = `
                <div class="flex items-center gap-2">
                    <input type="text" class="home-url-input w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com">
                </div>
            `;
            document.getElementById('redirectUrlsContainer').innerHTML = `
                <div class="flex items-center gap-2">
                    <input type="text" class="redirect-url-input w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none" placeholder="例如：https://example.com/oauth/callback">
                </div>
            `;
            document.getElementById('addClientBtn').textContent = '添加客户端';
            document.getElementById('cancelEditBtn').classList.add('hidden');
        }}

        function editClient(clientId, name, clientSecret, homeUrls, redirectUrls) {{
            editingClientId = clientId;
            document.getElementById('newClientName').value = name || '';
            document.getElementById('newClientId').value = clientId || '';
            document.getElementById('newClientSecret').value = clientSecret || '';

            // 设置主页链接
            const homeUrlsContainer = document.getElementById('homeUrlsContainer');
            homeUrlsContainer.innerHTML = '';
            if (homeUrls && homeUrls.length > 0) {{
                homeUrls.forEach(url => addHomeUrlInput(url));
            }} else {{
                addHomeUrlInput();
            }}

            // 设置重定向URL
            const redirectUrlsContainer = document.getElementById('redirectUrlsContainer');
            redirectUrlsContainer.innerHTML = '';
            if (redirectUrls && redirectUrls.length > 0) {{
                redirectUrls.forEach(url => addRedirectUrlInput(url));
            }} else {{
                addRedirectUrlInput();
            }}

            document.getElementById('addClientBtn').textContent = '更新客户端';
            document.getElementById('cancelEditBtn').classList.remove('hidden');

            // 滚动到表单
            document.querySelector('#tab-clients .bg-white').scrollIntoView({{ behavior: 'smooth' }});
        }}

        async function addClient() {{
            const name = document.getElementById('newClientName').value;
            const client_id = document.getElementById('newClientId').value;
            const client_secret = document.getElementById('newClientSecret').value;
            const home_urls = getHomeUrls();
            const redirect_urls = getRedirectUrls();

            if (!name) {{
                showToast('请输入客户端名称', 'error');
                return;
            }}

            if (redirect_urls.length === 0) {{
                showToast('请至少添加一个重定向 URL', 'error');
                return;
            }}

            const isEditing = editingClientId !== null;
            const endpoint = isEditing ? 'api/clients/update' : 'api/clients/add';
            const successMessage = isEditing ? '客户端更新成功！' : '客户端创建成功！';

            try {{
                const response = await fetch(basePath + endpoint, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    }},
                    body: JSON.stringify({{
                        name: name,
                        client_id: client_id,
                        client_secret: client_secret,
                        home_urls: home_urls,
                        redirect_urls: redirect_urls
                    }})
                }});
                const data = await response.json();

                if (data.success) {{
                    showToast(successMessage, 'success');
                    resetClientForm();
                    loadClients();
                }} else {{
                    showToast(data.message || (isEditing ? '更新失败' : '添加失败'), 'error');
                }}
            }} catch (err) {{
                console.error(isEditing ? '更新客户端失败:' : '添加客户端失败:', err);
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

        // 审计日志相关变量
        let currentLogPage = 0;
        const logsPerPage = 20;
        let currentLogFilter = '';

        // HTML 转义函数，防止 XSS 攻击
        function escapeHtml(text) {{
            if (text === null || text === undefined) return '';
            const div = document.createElement('div');
            div.textContent = String(text);
            return div.innerHTML;
        }}

        async function loadLogs() {{
            try {{
                const response = await fetch(basePath + `api/logs?limit=${{logsPerPage}}&offset=${{currentLogPage * logsPerPage}}&action=${{currentLogFilter}}`, {{
                    headers: {{ 'Authorization': 'Bearer ' + token }}
                }});
                const data = await response.json();
                if (!data.success) return;

                document.getElementById('logCount').textContent = `共 ${{data.total}} 条日志`;
                const tbody = document.getElementById('logTable');
                if (data.logs.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-12 text-center text-slate-400 font-medium">暂无日志</td></tr>';
                }} else {{
                    const actionLabels = {{
                        'LOGIN': {{ text: '登录', class: 'bg-blue-100 text-blue-600' }},
                        'LOGOUT': {{ text: '登出', class: 'bg-gray-100 text-gray-600' }},
                        'CLIENT_ADD': {{ text: '添加客户端', class: 'bg-green-100 text-green-600' }},
                        'CLIENT_UPDATE': {{ text: '更新客户端', class: 'bg-yellow-100 text-yellow-600' }},
                        'CLIENT_DELETE': {{ text: '删除客户端', class: 'bg-red-100 text-red-600' }},
                        'CONFIG_UPDATE': {{ text: '配置更新', class: 'bg-purple-100 text-purple-600' }},
                        'AUTHORIZE': {{ text: '授权', class: 'bg-indigo-100 text-indigo-600' }},
                        'TOKEN_EXCHANGE': {{ text: '令牌交换', class: 'bg-teal-100 text-teal-600' }},
                        'CLEAR_LOGS': {{ text: '清空日志', class: 'bg-orange-100 text-orange-600' }}
                    }};

                    tbody.innerHTML = data.logs.map(log => {{
                        const action = actionLabels[log.action] || {{ text: escapeHtml(log.action), class: 'bg-slate-100 text-slate-600' }};
                        return `
                            <tr class="hover:bg-slate-50/50 transition-colors">
                                <td class="px-6 py-4 text-sm text-slate-600">${{new Date(log.timestamp * 1000).toLocaleString()}}</td>
                                <td class="px-6 py-4">
                                    <span class="px-3 py-1 rounded-full text-xs font-bold ${{action.class}}">${{action.text}}</span>
                                </td>
                                <td class="px-6 py-4 text-sm text-slate-600">${{escapeHtml(log.details) || '-'}}</td>
                                <td class="px-6 py-4 text-sm text-slate-600">${{escapeHtml(log.user) || '-'}}</td>
                                <td class="px-6 py-4 text-sm text-slate-600 font-mono">${{escapeHtml(log.ip) || '-'}}</td>
                            </tr>
                        `;
                    }}).join('');
                }}

                // 更新分页按钮状态
                document.getElementById('prevLogPage').disabled = currentLogPage === 0;
                document.getElementById('nextLogPage').disabled = (currentLogPage + 1) * logsPerPage >= data.total;
                document.getElementById('logPageInfo').textContent = `第 ${{currentLogPage + 1}} 页`;
            }} catch (err) {{
                console.error('加载日志失败:', err);
            }}
        }}

        function changeLogPage(delta) {{
            currentLogPage += delta;
            if (currentLogPage < 0) currentLogPage = 0;
            loadLogs();
        }}

        async function clearLogs() {{
            if (!confirm('确定要清空所有审计日志吗？此操作不可恢复。')) return;

            try {{
                const response = await fetch(basePath + 'api/logs/clear', {{
                    method: 'POST',
                    headers: {{ 'Authorization': 'Bearer ' + token }}
                }});
                const data = await response.json();

                if (data.success) {{
                    showToast('日志已清空', 'success');
                    currentLogPage = 0;
                    loadLogs();
                }} else {{
                    showToast(data.message || '清空失败', 'error');
                }}
            }} catch (err) {{
                console.error('清空日志失败:', err);
                showToast('网络错误，请重试', 'error');
            }}
        }}

        // 日志过滤器事件监听
        document.getElementById('logFilter').addEventListener('change', function(e) {{
            currentLogFilter = e.target.value;
            currentLogPage = 0;
            loadLogs();
        }});

        loadConfig();
        loadSessions();
        loadClients();
        loadLogs();
        setInterval(loadSessions, 5000);
    </script>
</body>
</html>"""

    def _render_verify_page(
        self,
        code: str,
        auth_code: str,
        session_id: str,
        redirect_uri: str,
        state: str,
        scope: str = "openid profile",
        client: dict = None,
    ) -> str:
        verify_group_id = self._get_web_config("verify_group_id", "")
        enable_group_verify = self._get_web_config("enable_group_verify", True)
        enable_private_verify = self._get_web_config("enable_private_verify", True)
        theme_color = self._get_web_config("theme_color", "#50b6fe")
        icon_url = self._get_web_config(
            "icon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        favicon_url = self._get_web_config(
            "favicon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        poll_interval = self._get_web_config("poll_interval", 1)
        poll_interval_ms = max(1000, min(30000, poll_interval * 1000))

        client_name = client.get("name", "未知应用") if client else "未知应用"

        # 对 icon_url 进行 HTML 属性转义，防止 XSS 攻击
        icon_html = (
            f'<img src="{escape_html_attr(icon_url)}" class="h-16 w-16 object-cover rounded-lg" alt="icon">'
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
                        <p class="text-sm font-bold text-slate-700">{escape_html(scope_descriptions[s]["name"])}</p>
                        <p class="text-xs text-slate-500 mt-0.5">{escape_html(scope_descriptions[s]["desc"])}</p>
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
                        <p class="text-sm font-medium text-slate-700">{escape_html(", ".join(groups))}</p>
                    </div>
                </div>"""

        private_info = ""
        if enable_private_verify:
            private_info = """
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

        # 生成验证码 HTML
        code_chars_html = " ".join(
            [f'<span class="code-char">{escape_html(char)}</span>' for char in code]
        )

        # 从模板文件加载
        try:
            from .templates import template_manager

            template = template_manager.get_template("verify")
            return template.format(
                theme_color=escape_html(theme_color),
                icon_html=icon_html,
                favicon_url=escape_html(favicon_url),
                code=escape_html(code),
                code_chars_html=code_chars_html,
                session_id=escape_html(session_id),
                auth_code=escape_html(auth_code),
                redirect_uri=escape_html(redirect_uri),
                state=escape_html(state),
                client_name=escape_html(client_name),
                scope_items=scope_items,
                group_info=group_info,
                private_info=private_info,
                poll_interval_ms=poll_interval_ms,
            )
        except Exception as e:
            logger.error(f"加载模板失败: {e}，使用内置模板")
            return self._render_verify_page_builtin(
                theme_color,
                icon_html,
                favicon_url,
                code,
                code_chars_html,
                session_id,
                auth_code,
                redirect_uri,
                state,
                client_name,
                scope_items,
                group_info,
                private_info,
                poll_interval_ms,
            )

    def _render_verify_page_builtin(
        self,
        theme_color: str,
        icon_html: str,
        favicon_url: str,
        code: str,
        code_chars_html: str,
        session_id: str,
        auth_code: str,
        redirect_uri: str,
        state: str,
        client_name: str,
        scope_items: str,
        group_info: str,
        private_info: str,
        poll_interval_ms: int = 1000,
    ) -> str:
        """内置验证页面模板（备用）

        安全说明：
        - 所有外部输入都经过转义处理
        - theme_color 使用 CSS 转义
        - 其他字符串使用 HTML 转义
        """
        try:
            from .templates import template_manager

            template = template_manager.get_template("verify")
            return template.format(
                theme_color=escape_css_value(theme_color),
                icon_html=icon_html,
                favicon_url=escape_html_attr(favicon_url),
                code=escape_html(code),
                code_chars_html=code_chars_html,
                session_id=escape_html(session_id),
                auth_code=escape_html(auth_code),
                redirect_uri=escape_html(redirect_uri),
                state=escape_html(state),
                client_name=escape_html(client_name),
                scope_items=scope_items,
                group_info=group_info,
                private_info=private_info,
                poll_interval_ms=poll_interval_ms,
            )
        except Exception as e:
            logger.error(f"加载模板失败: {e}")
            return f"<html><body><h1>模板加载失败: {escape_html(str(e))}</h1></body></html>"

    def _render_verify_input_page(self, code: str, session_id: str) -> str:
        """渲染手动验证输入页面

        使用模板文件渲染验证页面，支持主题颜色、图标等自定义。
        """
        theme_color = self._get_web_config("theme_color", "#50b6fe")
        icon_url = self._get_web_config(
            "icon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        favicon_url = self._get_web_config(
            "favicon_url",
            "https://cloud.chuyel.top/f/PkZsP/tu%E5%B7%B2%E5%8E%BB%E5%BA%95.png",
        )
        poll_interval = self._get_web_config("poll_interval", 1)
        poll_interval_ms = max(1000, min(30000, poll_interval * 1000))

        # 安全处理 icon_html，转义 URL
        icon_html = (
            f'<img src="{escape_html_attr(icon_url)}" class="h-16 w-16 object-cover rounded-lg" alt="icon">'
            if icon_url
            else """<svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>"""
        )

        # 从模板文件加载
        try:
            from .templates import template_manager

            template = template_manager.get_template("verify_input")
            return template.format(
                theme_color=escape_css_value(theme_color),
                icon_html=icon_html,
                favicon_url=escape_html_attr(favicon_url),
                code=escape_html(code),
                poll_interval_ms=poll_interval_ms,
            )
        except Exception as e:
            logger.error(f"加载模板失败: {e}，使用内置模板")
            return self._render_verify_input_page_builtin(
                theme_color, icon_html, favicon_url, code, poll_interval_ms
            )

    def _render_verify_input_page_builtin(
        self,
        theme_color: str,
        icon_html: str,
        favicon_url: str,
        code: str,
        poll_interval_ms: int = 1000,
    ) -> str:
        """内置验证输入页面模板（备用）

        安全说明：
        - 此页面仅用于查询验证码状态
        - 用户身份验证必须通过 QQ 消息（可信通道）完成
        - 不允许用户自填 user_id，防止身份伪造
        """
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OIDC 验证 - 验证码状态</title>
    <link rel="icon" type="image/png" href="{escape_html_attr(favicon_url)}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    colors: {{
                        primary: '{escape_js_string(theme_color)}',
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ font-family: 'Inter', -apple-system, sans-serif; }}
        .glass {{ background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); }}
        .bg-primary {{ background-color: {escape_css_value(theme_color)}; }}
        .text-primary {{ color: {escape_css_value(theme_color)}; }}
        .shadow-primary {{ box-shadow: 0 10px 15px -3px {escape_css_value(theme_color)}33; }}
    </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen flex items-center justify-center p-4 bg-[radial-gradient(circle_at_top_left,_var(--tw-gradient-stops))] from-indigo-100 via-slate-50 to-teal-50">
    <div class="max-w-md w-full">
        <div class="glass rounded-[2.5rem] shadow-2xl shadow-primary/30 p-8 md:p-10 border border-white">
            <div class="text-center mb-10">
                <div class="inline-flex items-center justify-center w-16 h-16 mb-6">
                    {icon_html}
                </div>
                <h1 class="text-3xl font-bold text-slate-800 tracking-tight">验证状态查询</h1>
                <p class="text-slate-500 mt-2 font-medium">请通过 QQ 群聊/私聊发送验证码完成验证</p>
            </div>

            <div class="bg-amber-50 border border-amber-200 rounded-2xl p-4 mb-6">
                <div class="flex items-start gap-3">
                    <svg class="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div>
                        <p class="text-sm font-semibold text-amber-800">安全提示</p>
                        <p class="text-sm text-amber-700 mt-1">为防止身份伪造，请通过 QQ 机器人发送验证码完成验证。验证码有效期为 5 分钟。</p>
                    </div>
                </div>
            </div>

            <form id="verifyForm" class="space-y-6">
                <div>
                    <label class="block text-sm font-semibold text-slate-700 mb-2 ml-1">验证码</label>
                    <input type="text" id="code" name="code" value="{escape_html_attr(code)}" required
                        class="w-full px-4 py-3.5 bg-slate-50 border border-slate-200 rounded-2xl focus:ring-4 focus:ring-primary/10 focus:border-primary transition-all outline-none placeholder:text-slate-400 font-mono text-lg tracking-wider"
                        placeholder="请输入验证码">
                </div>
                <button type="submit"
                    class="w-full py-4 bg-primary hover:opacity-90 text-white rounded-2xl font-bold text-lg shadow-lg shadow-primary/30 transition-all active:scale-[0.98] flex items-center justify-center gap-2">
                    <span>查询验证状态</span>
                </button>
            </form>

            <div id="message" class="mt-6 text-center p-4 rounded-2xl text-sm font-bold hidden"></div>
        </div>
        <p class="text-center text-slate-400 text-sm mt-8">Powered by <a href="https://github.com/AstrBotDevs/AstrBot" target="_blank" class="text-primary hover:opacity-80">AstrBot</a> & <a href="https://www.chuyel.cn" target="_blank" class="text-primary hover:opacity-80">初叶🍂竹叶-Furry控</a></p>
    </div>

    <script>
        var POLL_INTERVAL_MS = {poll_interval_ms};

        document.getElementById('verifyForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const code = document.getElementById('code').value;
            const message = document.getElementById('message');
            const btn = e.target.querySelector('button');

            btn.disabled = true;
            const originalBtnContent = btn.innerHTML;
            btn.innerHTML = '<svg class="animate-spin h-5 w-5 text-white" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';

            try {{
                const response = await fetch('../api/verify', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ code }})
                }});
                const data = await response.json();

                message.classList.remove('hidden', 'bg-teal-50', 'text-teal-600', 'bg-rose-50', 'text-rose-600', 'bg-amber-50', 'text-amber-600');

                if (data.success) {{
                    message.classList.add('bg-teal-50', 'text-teal-600');
                    message.textContent = '验证成功！正在跳转...';
                    if (data.redirect_url) {{
                        setTimeout(() => {{ window.location.href = data.redirect_url; }}, 1500);
                    }}
                }} else if (data.pending) {{
                    message.classList.add('bg-amber-50', 'text-amber-600');
                    message.textContent = data.message || '验证码有效，请通过 QQ 发送验证码完成验证';
                    btn.disabled = false;
                    btn.innerHTML = originalBtnContent;
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
</html>"""


@register("astrbot_plugin_chuyeoidc", "chuyegzs", "OIDC登录插件", "1.0.6")
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
        self.config_manager: ConfigManager | None = None
        self.client_manager: ClientManager | None = None
        self.audit_log_manager: AuditLogManager | None = None
        self.oidc_server: OIDCServer | None = None
        self.web_handler: WebHandler | None = None
        self._cleanup_task: asyncio.Task | None = None

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
        # 初始化审计日志管理器，使用与配置管理器相同的数据目录
        data_dir = StarTools.get_data_dir() / "chuyeoidc"
        self.audit_log_manager = AuditLogManager(data_dir)
        # 初始化 SessionManager 用于会话持久化
        self.session_manager = SessionManager(data_dir)
        self.oidc_server = OIDCServer(
            self, self.config_manager, self.client_manager, self.session_manager
        )
        self.web_handler = WebHandler(
            self,
            self.oidc_server,
            self.config_manager,
            self.client_manager,
            self.audit_log_manager,
        )

        port = self._get_config("web_port", 33145)
        secure_path = self._get_config("secure_path", "chuyeoidc")

        if not secure_path:
            logger.error("安全入口路径不能为空")
            secure_path = "chuyeoidc"

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.web_handler.handle_root)

        # 检查端口是否被占用，如果被占用则等待释放
        import socket

        def is_port_in_use(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(("0.0.0.0", port)) == 0

        max_wait = 10  # 最大等待10秒
        waited = 0
        while is_port_in_use(port) and waited < max_wait:
            logger.warning(f"端口 {port} 被占用，等待释放... ({waited + 1}/{max_wait})")
            await asyncio.sleep(1)
            waited += 1

        if is_port_in_use(port):
            logger.error(f"端口 {port} 仍然被占用，无法启动服务")
            raise OSError(f"端口 {port} 被占用")

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

        # 停止自动保存任务
        if self.oidc_server:
            self.oidc_server.stop_auto_save()

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # 保存所有会话数据
        if hasattr(self, "session_manager") and self.session_manager:
            await self.session_manager.save_all()
            logger.info("会话数据已保存")

        # 停止 Web 服务（添加异常处理避免重启时出错）
        if self.oidc_server:
            try:
                if self.oidc_server.site:
                    await self.oidc_server.site.stop()
                    logger.debug("Site 已停止")
            except Exception as e:
                logger.debug(f"停止 site 时出错（可能已停止）: {e}")

            try:
                if self.oidc_server.runner:
                    await self.oidc_server.runner.cleanup()
                    logger.debug("Runner 已清理")
            except Exception as e:
                logger.debug(f"清理 runner 时出错（可能已清理）: {e}")

            # 强制关闭所有连接，确保端口立即释放
            try:
                if self.oidc_server.app:
                    # 关闭所有活跃的连接
                    for site in list(getattr(self.oidc_server.runner, "_sites", [])):
                        try:
                            await site.stop()
                        except:
                            pass
            except Exception as e:
                logger.debug(f"关闭连接时出错: {e}")

            # 等待端口释放，避免重启时出现 "地址已被使用" 错误
            # 需要足够长的时间让操作系统完全释放端口
            logger.debug("等待端口释放...")
            await asyncio.sleep(5)

        logger.info("OIDC登录插件已停止")

    async def _periodic_cleanup(self):
        """定期清理过期数据和密钥轮换

        每30秒执行一次清理，确保过期验证码和令牌能及时被清理
        同时定期执行密钥轮换
        """
        while True:
            try:
                await asyncio.sleep(30)
                if self.oidc_server:
                    await self.oidc_server.cleanup_expired()

                if self.oidc_server and self.oidc_server.key_manager:
                    try:
                        rotated = await self.oidc_server.key_manager.rotate_keys()
                        if rotated:
                            self.audit_log_manager.log(
                                action="KEY_ROTATION",
                                details="密钥轮换成功",
                                user="system",
                                ip="",
                            )
                    except Exception as e:
                        logger.error(f"密钥轮换失败: {e}")
                        self.audit_log_manager.log(
                            action="KEY_ROTATION_FAILED",
                            details=f"密钥轮换失败: {str(e)}",
                            user="system",
                            ip="",
                        )
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
            yield event.plain_result("验证成功！您已通过OIDC认证。")
        else:
            yield event.plain_result(f"验证失败：{result}")

    @filter.regex(r"^\d{4,8}$")
    async def verify_code_direct(self, event: AstrMessageEvent):
        """直接验证码验证 - 仅验证成功时回复

        为了避免频繁请求干扰用户，只有当验证码正确且验证成功时才发送成功指令。
        验证码不存在、已过期、已使用或验证失败等情况均不回复任何消息。
        """
        message_str = event.get_message_str().strip()

        if not message_str.isdigit():
            return

        if not self.oidc_server:
            return

        code = message_str

        # 先检查验证码是否存在且有效，避免不必要的群聊检查
        verify_code_data = self.oidc_server.session_manager.get_verify_code(code)
        if not verify_code_data:
            # 验证码不存在，静默处理（不回复）
            return

        # 检查验证码是否已使用
        if verify_code_data.get("used", False):
            # 验证码已使用，静默处理
            return

        # 检查验证码是否过期
        expire_seconds = self._get_web_config("code_expire_seconds", 300)
        if time.time() - verify_code_data.get("created_at", 0) > expire_seconds:
            # 验证码已过期，静默处理
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

        if is_group:
            # 群聊消息
            if not enable_group_verify:
                return
            # 检查是否在允许的群聊中
            allowed_groups = [
                g.strip() for g in verify_group_id.split(",") if g.strip()
            ]
            if allowed_groups and group_id not in allowed_groups:
                return
        else:
            # 私聊消息
            if not enable_private_verify:
                return

        user_id = event.get_sender_id()
        user_name = event.get_sender_name()

        # 执行验证
        success, result = await self.oidc_server.verify_code_submit(
            code, user_id, {"id": user_id, "name": user_name}
        )

        # 只有验证成功时才发送成功指令
        if success:
            logger.info(
                f"验证码验证成功: user_id={user_id}, session_id={result[:8]}..."
            )
            yield event.plain_result("✅ 验证成功！您已通过OIDC认证。")
