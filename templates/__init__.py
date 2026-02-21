"""
HTML 模板模块

此模块包含 OIDC 插件的所有 HTML 模板。
模板使用 Python 字符串格式化，支持动态变量替换。

安全说明：
- 所有模板变量在渲染时应使用安全转义方法
- 提供 escape_html, escape_html_attr, escape_js_string, escape_css_value 等转义函数
- 根据变量在模板中的上下文选择合适的转义方法
"""

import html
import os
import re
from collections.abc import Callable
from typing import Any, Optional


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
    text = text.replace(";", "")
    text = text.replace("{", "")
    text = text.replace("}", "")
    text = text.replace("(", "")
    text = text.replace(")", "")
    text = text.replace("'", "")
    text = text.replace('"', "")
    return text


class TemplateManager:
    """模板管理器

    负责加载和管理 HTML 模板文件。
    支持从文件系统加载模板，便于维护和修改。

    安全特性：
    - 支持自动变量转义
    - 提供多种上下文相关的转义函数
    - 缓存机制提高性能
    """

    def __init__(self, templates_dir: str | None = None):
        """初始化模板管理器

        Args:
            templates_dir: 模板目录路径，默认为当前目录
        """
        if templates_dir is None:
            self.templates_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.templates_dir = templates_dir

        self._cache: dict[str, str] = {}
        self._escape_functions: dict[str, Callable[[str], str]] = {
            "html": escape_html,
            "attr": escape_html_attr,
            "js": escape_js_string,
            "css": escape_css_value,
        }

    def get_template(self, template_name: str) -> str:
        """获取模板内容

        Args:
            template_name: 模板文件名（不含扩展名）

        Returns:
            模板内容字符串

        Raises:
            FileNotFoundError: 模板文件不存在
            ValueError: 模板名称包含非法字符（路径遍历风险）
        """
        # 验证模板路径安全，防止路径遍历攻击
        if not self.validate_template_path(template_name):
            raise ValueError(f"模板名称包含非法字符: {template_name}")

        if template_name in self._cache:
            return self._cache[template_name]

        template_path = os.path.join(self.templates_dir, f"{template_name}.html")
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"模板文件不存在: {template_path}")

        with open(template_path, encoding="utf-8") as f:
            content = f.read()

        self._cache[template_name] = content
        return content

    def render(self, template_name: str, **kwargs) -> str:
        """渲染模板（不进行自动转义，需要调用者手动转义）

        警告：此方法不进行自动转义，调用者需要确保所有变量已经过适当转义。
        建议使用 render_safe 方法进行安全渲染。

        Args:
            template_name: 模板文件名（不含扩展名）
            **kwargs: 模板变量

        Returns:
            渲染后的 HTML 字符串
        """
        template = self.get_template(template_name)
        return template.format(**kwargs)

    def render_safe(
        self, template_name: str, escape_mode: str = "html", **kwargs
    ) -> str:
        """安全渲染模板（自动转义所有变量）

        根据指定的转义模式，对所有变量进行自动转义。

        Args:
            template_name: 模板文件名（不含扩展名）
            escape_mode: 转义模式，可选值：html, attr, js, css
            **kwargs: 模板变量

        Returns:
            渲染后的安全 HTML 字符串

        Raises:
            ValueError: 无效的转义模式
        """
        if escape_mode not in self._escape_functions:
            raise ValueError(
                f"无效的转义模式: {escape_mode}，可选值: {list(self._escape_functions.keys())}"
            )

        escape_func = self._escape_functions[escape_mode]
        safe_kwargs = {}

        for key, value in kwargs.items():
            if isinstance(value, str):
                safe_kwargs[key] = escape_func(value)
            elif isinstance(value, (int, float, bool)):
                safe_kwargs[key] = value
            elif value is None:
                safe_kwargs[key] = ""
            else:
                safe_kwargs[key] = escape_func(str(value))

        template = self.get_template(template_name)
        return template.format(**safe_kwargs)

    def render_with_escapes(
        self, template_name: str, escape_map: dict[str, str], **kwargs
    ) -> str:
        """使用指定转义模式渲染模板

        为每个变量指定不同的转义模式。

        Args:
            template_name: 模板文件名（不含扩展名）
            escape_map: 变量名到转义模式的映射，如 {"title": "html", "url": "attr"}
            **kwargs: 模板变量

        Returns:
            渲染后的安全 HTML 字符串

        示例:
            template_manager.render_with_escapes(
                "my_template",
                escape_map={"title": "html", "url": "attr", "color": "css"},
                title="Hello",
                url="https://example.com",
                color="#4f46e5"
            )
        """
        safe_kwargs = {}

        for key, value in kwargs.items():
            escape_mode = escape_map.get(key, "html")

            if escape_mode not in self._escape_functions:
                escape_mode = "html"

            escape_func = self._escape_functions[escape_mode]

            if isinstance(value, str):
                safe_kwargs[key] = escape_func(value)
            elif isinstance(value, (int, float, bool)):
                safe_kwargs[key] = value
            elif value is None:
                safe_kwargs[key] = ""
            else:
                safe_kwargs[key] = escape_func(str(value))

        template = self.get_template(template_name)
        return template.format(**safe_kwargs)

    def clear_cache(self):
        """清除模板缓存"""
        self._cache.clear()

    def validate_template_path(self, template_name: str) -> bool:
        """验证模板路径是否安全

        防止路径遍历攻击。

        Args:
            template_name: 模板文件名（不含扩展名）

        Returns:
            路径是否安全
        """
        if not template_name:
            return False
        if ".." in template_name:
            return False
        if "/" in template_name or "\\" in template_name:
            return False
        if not re.match(r"^[a-zA-Z0-9_-]+$", template_name):
            return False
        return True


template_manager = TemplateManager()
