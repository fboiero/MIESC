from src.llm.openllama_helper import OpenLLaMAHelper


def test_parse_priorities_accepts_wrapped_json():
    helper = OpenLLaMAHelper()
    response = """
    Priority assessment:
    {
        "priorities": [
            {"index": 0, "priority": 9, "reason": "Critical exploit path"}
        ]
    }
    """

    priorities = helper._parse_priorities(response)

    assert priorities == {0: {"priority": 9, "reason": "Critical exploit path"}}


def test_parse_priorities_repairs_common_llm_json_errors():
    helper = OpenLLaMAHelper()
    response = """
    ```json
    {
        priorities: [
            {index: 2, priority: 7, reason: "Likely reachable",},
        ],
    }
    ```
    """

    priorities = helper._parse_priorities(response)

    assert priorities == {2: {"priority": 7, "reason": "Likely reachable"}}


def test_parse_priorities_repairs_invalid_backslash_escapes():
    helper = OpenLLaMAHelper()
    response = r'{"priorities": [{"index": 1, "priority": 6, "reason": "pattern \d+ matched"}]}'

    priorities = helper._parse_priorities(response)

    assert priorities[1]["priority"] == 6
    assert priorities[1]["reason"] == r"pattern \d+ matched"


def test_parse_priorities_returns_empty_on_unparseable_response():
    helper = OpenLLaMAHelper()

    assert helper._parse_priorities("not json") == {}
