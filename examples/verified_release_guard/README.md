# Verified Release Guard

This example is packaged into the `runmantle` CLI so it works from an installed
wheel, outside the source tree:

```bash
mkdir /tmp/runmantle-release-guard
runmantle init /tmp/runmantle-release-guard
cd /tmp/runmantle-release-guard
runmantle run || test $? -eq 3
runmantle verify || test $? -eq 4
runmantle resume || test $? -eq 5
runmantle resume --approve-current-plan
runmantle inspect --json
```

The nonzero exits are intentional incomplete/failed boundaries, not shell
errors. See [the full guide](../../docs/verified-release-guard.md).

The production OpenAI adapter variant uses an offline SDK model:

```bash
env -u OPENAI_API_KEY python -m examples.verified_release_guard.openai_offline
```
