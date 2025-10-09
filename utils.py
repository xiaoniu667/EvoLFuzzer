from datetime import datetime, date
from decimal import Decimal
from typing import Any


def convert_to_serializable(obj: Any) -> Any:
    """递归地将非 JSON 可序列化对象转换为可序列化类型"""
    if isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {str(key): convert_to_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, Decimal):
        return str(obj)  # 将 Decimal 转换为字符串
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()  # 将日期时间转换为 ISO 格式字符串
    else:
        return str(obj)  # 其他非标准类型转换为字符串