"""
MCP 工具参数验证器
==================
JSON Schema 验证和自定义验证规则
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from .registry import ToolMetadata

logger = logging.getLogger(__name__)


@dataclass
class ValidationError:
    """验证错误"""
    field: str
    message: str
    code: str


@dataclass
class ValidationResult:
    """验证结果"""
    valid: bool
    errors: list[ValidationError] = None
    warnings: list[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []

    @property
    def is_valid(self) -> bool:
        return self.valid and len(self.errors) == 0

    def add_error(self, field: str, message: str, code: str = "error"):
        self.errors.append(ValidationError(field=field, message=message, code=code))
        self.valid = False

    def add_warning(self, message: str):
        self.warnings.append(message)


def validate_tool_params(
    tool: ToolMetadata,
    params: dict,
    strict: bool = False,
) -> ValidationResult:
    """
    验证工具参数

    Args:
        tool: 工具元数据
        params: 输入参数
        strict: 是否严格模式 (不允许额外字段)

    Returns:
        ValidationResult
    """
    result = ValidationResult(valid=True)
    schema = tool.input_schema

    if not schema:
        # 没有 schema，任何参数都有效
        return result

    properties = schema.get("properties", {})
    required = schema.get("required", [])

    # 检查必需字段
    for field in required:
        if field not in params or params[field] is None:
            result.add_error(field, f"Required field '{field}' is missing", "required")

    # 检查每个提供的参数
    for field, value in params.items():
        if field not in properties:
            if strict:
                result.add_error(field, f"Unknown field '{field}'", "unknown_field")
            else:
                result.add_warning(f"Ignoring unknown field '{field}'")
            continue

        prop_schema = properties[field]
        field_errors = _validate_field(field, value, prop_schema)
        result.errors.extend(field_errors)
        if field_errors:
            result.valid = False

    # 检查额外字段
    if strict:
        known_fields = set(properties.keys())
        extra_fields = set(params.keys()) - known_fields
        for field in extra_fields:
            result.add_error(field, f"Extra field '{field}' not allowed in strict mode", "extra_field")

    return result


def _validate_field(field: str, value: Any, schema: dict) -> list[ValidationError]:
    """验证单个字段"""
    errors = []

    # 类型检查
    expected_type = schema.get("type")
    if expected_type:
        type_errors = _check_type(field, value, expected_type)
        errors.extend(type_errors)

    # 枚举检查
    if "enum" in schema:
        if value not in schema["enum"]:
            errors.append(ValidationError(
                field=field,
                message=f"Value must be one of: {schema['enum']}",
                code="enum",
            ))

    # 字符串模式
    if expected_type == "string" and isinstance(value, str):
        if "pattern" in schema:
            import re
            if not re.match(schema["pattern"], value):
                errors.append(ValidationError(
                    field=field,
                    message=f"String does not match pattern: {schema['pattern']}",
                    code="pattern",
                ))

        if "minLength" in schema:
            if len(value) < schema["minLength"]:
                errors.append(ValidationError(
                    field=field,
                    message=f"String must be at least {schema['minLength']} characters",
                    code="minLength",
                ))

        if "maxLength" in schema:
            if len(value) > schema["maxLength"]:
                errors.append(ValidationError(
                    field=field,
                    message=f"String must be at most {schema['maxLength']} characters",
                    code="maxLength",
                ))

    # 数字范围
    if expected_type in ("integer", "number") and isinstance(value, (int, float)):
        if "minimum" in schema:
            if value < schema["minimum"]:
                errors.append(ValidationError(
                    field=field,
                    message=f"Number must be >= {schema['minimum']}",
                    code="minimum",
                ))

        if "maximum" in schema:
            if value > schema["maximum"]:
                errors.append(ValidationError(
                    field=field,
                    message=f"Number must be <= {schema['maximum']}",
                    code="maximum",
                ))

    # 数组检查
    if expected_type == "array" and isinstance(value, list):
        if "minItems" in schema:
            if len(value) < schema["minItems"]:
                errors.append(ValidationError(
                    field=field,
                    message=f"Array must have at least {schema['minItems']} items",
                    code="minItems",
                ))

        if "maxItems" in schema:
            if len(value) > schema["maxItems"]:
                errors.append(ValidationError(
                    field=field,
                    message=f"Array must have at most {schema['maxItems']} items",
                    code="maxItems",
                ))

        if "items" in schema:
            item_schema = schema["items"]
            for i, item in enumerate(value):
                item_errors = _validate_field(f"{field}[{i}]", item, item_schema)
                errors.extend(item_errors)

    return errors


def _check_type(field: str, value: Any, expected_type: str) -> list[ValidationError]:
    """检查值类型"""
    errors = []

    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    expected_python_type = type_map.get(expected_type)
    if expected_python_type and not isinstance(value, expected_python_type):
        # 特殊处理：int 可以是 float
        if expected_type == "integer" and isinstance(value, float) and value.is_integer():
            return errors

        errors.append(ValidationError(
            field=field,
            message=f"Expected type '{expected_type}', got '{type(value).__name__}'",
            code="type",
        ))

    return errors
