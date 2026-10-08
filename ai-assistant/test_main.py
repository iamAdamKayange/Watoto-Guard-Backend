import asyncio
import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException

import main


class FakeResponse:
    text = "Taarifa ya kifaa haipo kwenye rekodi."


class FakeModels:
    def __init__(self):
        self.args = None

    def generate_content(self, **kwargs):
        self.args = kwargs
        return FakeResponse()


class FakeClient:
    latest = None

    def __init__(self, **kwargs):
        self.models = FakeModels()
        FakeClient.latest = self


class AssistantTests(unittest.TestCase):
    def request(self):
        return main.AnswerRequest(
            language="sw",
            messages=[main.Message(role="user", content="Taarifa ya mtoto wangu?")],
            context={"children": [{"label": "Mtoto 1", "deviceStatus": "OFFLINE"}]},
        )

    def test_requires_authenticated_node_service_secret(self):
        with patch.dict(os.environ, {"AI_ASSISTANT_SHARED_SECRET": "x" * 32, "GEMINI_API_KEY": "test"}):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.answer(self.request(), "wrong"))
        self.assertEqual(caught.exception.status_code, 401)

    def test_uses_only_bounded_node_scoped_context_and_returns_answer(self):
        with patch.dict(os.environ, {"AI_ASSISTANT_SHARED_SECRET": "s" * 40, "GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "test-model"}), patch.object(main.genai, "Client", FakeClient):
            result = asyncio.run(main.answer(self.request(), "s" * 40))
        self.assertEqual(result["answer"], FakeResponse.text)
        args = FakeClient.latest.models.args
        self.assertEqual(args["model"], "test-model")
        self.assertIn('"deviceStatus":"OFFLINE"', args["contents"][0].parts[0].text)
        self.assertIn("Kiswahili", args["config"].system_instruction)

    def test_context_size_is_capped_before_provider_call(self):
        request = self.request()
        request.context = {"large": "x" * 12_001}
        with patch.dict(os.environ, {"AI_ASSISTANT_SHARED_SECRET": "s" * 40, "GEMINI_API_KEY": "test-key"}):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.answer(request, "s" * 40))
        self.assertEqual(caught.exception.status_code, 413)


if __name__ == "__main__":
    unittest.main()
