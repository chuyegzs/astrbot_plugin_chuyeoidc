"""
HTML 模板模块

此模块包含 OIDC 插件的所有 HTML 模板。
模板使用 Python 字符串格式化，支持动态变量替换。
"""

import os
from typing import Optional


class TemplateManager:
    """模板管理器

    负责加载和管理 HTML 模板文件。
    支持从文件系统加载模板，便于维护和修改。
    """

    def __init__(self, templates_dir: Optional[str] = None):
        """初始化模板管理器

        Args:
            templates_dir: 模板目录路径，默认为当前目录
        """
        if templates_dir is None:
            self.templates_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.templates_dir = templates_dir

        self._cache = {}

    def get_template(self, template_name: str) -> str:
        """获取模板内容

        Args:
            template_name: 模板文件名（不含扩展名）

        Returns:
            模板内容字符串

        Raises:
            FileNotFoundError: 模板文件不存在
        """
        # 检查缓存
        if template_name in self._cache:
            return self._cache[template_name]

        # 从文件加载
        template_path = os.path.join(self.templates_dir, f"{template_name}.html")
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"模板文件不存在: {template_path}")

        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()

        # 缓存模板
        self._cache[template_name] = content
        return content

    def render(self, template_name: str, **kwargs) -> str:
        """渲染模板

        Args:
            template_name: 模板文件名（不含扩展名）
            **kwargs: 模板变量

        Returns:
            渲染后的 HTML 字符串
        """
        template = self.get_template(template_name)
        return template.format(**kwargs)

    def clear_cache(self):
        """清除模板缓存"""
        self._cache.clear()


# 全局模板管理器实例
template_manager = TemplateManager()
