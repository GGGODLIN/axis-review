import json
import re
from pathlib import Path

from .llm import ChatError
from .repo_tools import TOOLS, execute


class AxisError(RuntimeError):
  pass


def validate(value, schema: dict, path: str = "$", /) -> None:
  if "anyOf" in schema:
    for option in schema["anyOf"]:
      try:
        validate(value, option, path)
        return
      except AxisError:
        continue
    raise AxisError(f"{path} does not match an allowed schema type or value")
  if "enum" in schema and value not in schema["enum"]:
    raise AxisError(f"{path} has an invalid enum value")
  kind = schema.get("type")
  if kind is None:
    return
  expected = {"object": dict, "array": list, "string": str, "integer": int,
              "boolean": bool, "null": type(None)}[kind]
  if type(value) is not expected:
    raise AxisError(f"{path} must be {kind}")
  if kind == "object":
    properties = schema.get("properties", {})
    if (set(schema.get("required", [])) - value.keys()
        or schema.get("additionalProperties") is False and value.keys() - properties.keys()):
      raise AxisError(f"{path} has missing or unexpected fields")
    for key in properties.keys() & value.keys():
      validate(value[key], properties[key], f"{path}.{key}")
    if "if" in schema:
      try:
        validate(value, schema["if"], path)
      except AxisError:
        pass
      else:
        validate(value, schema["then"], path)
  elif kind == "array":
    if len(value) < schema.get("minItems", 0):
      raise AxisError(f"{path} has too few items")
    for index, item in enumerate(value):
      validate(item, schema["items"], f"{path}[{index}]")
  elif kind == "string" and schema.get("minLength", 0) > len(value.strip()):
    raise AxisError(f"{path} must contain text")
  elif kind == "integer" and "minimum" in schema and value < schema["minimum"]:
    raise AxisError(f"{path} is below its allowed minimum")


def _object(pairs):
  values = dict(pairs)
  if len(values) != len(pairs):
    raise ValueError("Duplicate JSON key")
  return values


def _invalid_constant(_):
  raise ValueError("Non-JSON constant")


def _parse(content, schema: dict) -> dict:
  if not isinstance(content, str):
    raise AxisError("Final message has no JSON text")
  content = content.strip()
  fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
  if fenced:
    content = fenced[1]
  try:
    result = json.loads(content, object_pairs_hook=_object, parse_constant=_invalid_constant)
    json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
  except UnicodeEncodeError:
    raise AxisError("Final message contains invalid Unicode") from None
  except (ValueError, RecursionError):
    raise AxisError("Final message is malformed JSON") from None
  if not isinstance(result, dict):
    raise AxisError("Final message must be a JSON object")
  validate(result, schema)
  return result


def _message(response: dict) -> dict:
  try:
    choice = response["choices"][0]
    message = choice["message"]
  except (KeyError, IndexError, TypeError):
    raise AxisError("Chat response has no assistant message") from None
  if not isinstance(message, dict):
    raise AxisError("Chat response has an invalid assistant message")
  if choice.get("finish_reason") in ("length", "content_filter"):
    raise AxisError("Chat provider stopped before completing the message")
  return message


def _tool_exchange(message, calls, root: Path, base_sha, head_sha) -> list[dict]:
  if not isinstance(calls, list):
    raise AxisError("Invalid tool calls")
  assistant = {"role": "assistant", "content": message.get("content"), "tool_calls": []}
  if assistant["content"] is not None and not isinstance(assistant["content"], str):
    raise AxisError("Invalid tool call envelope")
  results = []
  seen = set()
  for call in calls:
    try:
      name, arguments, call_id = call["function"]["name"], call["function"]["arguments"], call["id"]
      if (not all(isinstance(value, str) for value in (name, arguments, call_id))
          or not call_id or call_id in seen or call.get("type") != "function"):
        raise TypeError
    except (KeyError, TypeError):
      raise AxisError("Invalid tool call envelope") from None
    seen.add(call_id)
    assistant["tool_calls"].append({"id": call_id, "type": "function",
                                    "function": {"name": name, "arguments": arguments}})
    try:
      args = json.loads(arguments, object_pairs_hook=_object, parse_constant=_invalid_constant)
      if not isinstance(args, dict):
        raise ValueError
      json.dumps(args, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except UnicodeEncodeError:
      raise AxisError("Tool arguments contain invalid Unicode") from None
    except (ValueError, RecursionError):
      content = "Tool error: arguments must be a JSON object"
    else:
      content = execute(name, args, root, base_sha=base_sha, head_sha=head_sha)
    results.append({"role": "tool", "tool_call_id": call_id, "content": content})
  try:
    json.dumps(assistant, ensure_ascii=False).encode("utf-8")
  except UnicodeEncodeError:
    raise AxisError("Tool call envelope contains invalid Unicode") from None
  return [assistant, *results]


def run_json_with_record(client, *, phase, axis, endpoint, model, system, user, schema, tools: bool,
                         root: Path | None = None, repair: bool | None = None,
                         base_sha: str | None = None, head_sha: str | None = None):
  if tools and root is None:
    raise ValueError("Checkout is required when repository tools are enabled")
  can_repair = phase in {"initial", "coverage_repair", "primary", "neutral", "adversarial"}
  if repair is not None:
    can_repair = repair and can_repair
  messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
  tool_turns = 0
  while True:
    allow_tools = tools and tool_turns < client.config.max_tool_turns
    try:
      response, record = client.chat(
        phase=phase, axis=axis, endpoint=endpoint, model=model, messages=messages,
        tools=TOOLS if allow_tools else None,
        response_format=None if allow_tools else {"type": "json_object"},
      )
    except ChatError as error:
      raise AxisError(str(error)) from None
    message = _message(response)
    calls = message.get("tool_calls")
    if calls is not None and calls != []:
      if not allow_tools:
        raise AxisError("Tool-turn limit exhausted" if tools else "Tools are disabled")
      messages.extend(_tool_exchange(message, calls, root, base_sha, head_sha))
      tool_turns += 1
      continue
    try:
      return _parse(message.get("content"), schema), record
    except AxisError:
      if not can_repair:
        raise
      content = message.get("content")
      repair_text = content.encode("utf-8", errors="backslashreplace").decode() if isinstance(content, str) else ""
      messages.extend([{"role": "assistant", "content": repair_text},
                       {"role": "user", "content": "Return only JSON matching the schema in the system message."}])
      can_repair = False
      tools = False


def run_json(*args, **kwargs) -> dict:
  return run_json_with_record(*args, **kwargs)[0]
