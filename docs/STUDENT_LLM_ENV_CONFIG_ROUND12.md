# Student LLM environment/config defaults

Round 12 makes student-solution LLM configuration dashboard-visible and env-file driven.

The dashboard reads safe defaults from:

- external env folder configured in dashboard settings, e.g. `C:\Users\DikshyantAcharya\Personal\env`
- project `.env.local`
- project `.env`

The external env loader now also reads:

- `.env`
- `env`
- `env.txt`
- `student_agent.env`
- `student_llm.env`
- `academiccloud.env`
- `saia.env`

Only env var names and key-present booleans are shown in the browser. Secret values are never returned.

Recommended external env setup:

```env
STUDENT_AGENT_LLM=1
STUDENT_LLM_ENABLED=1
STUDENT_LLM_API_BASE=https://chat-ai.academiccloud.de/v1
STUDENT_LLM_MODEL=mistral-large-3-675b-instruct-2512
STUDENT_LLM_API_KEY_ENV=ACADEMIC_CLOUD_API_KEY
ACADEMIC_CLOUD_API_KEY=your_real_key_here
```

Evaluate Solution now shows the resolved provider/base/model/key-env and uses those defaults automatically when running `solution_agentic_research_like.py`.

The student solution logs LLM usage as:

- `student.llm.start ...`
- `student.llm.done ...`

and every evaluation writes `student_llm_config.json` under the evaluation output folder.
