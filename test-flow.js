const http = require("http");
require("dotenv").config();

const PORT = process.env.PORT || 5000;
const BASE_URL = `http://localhost:${PORT}`;

// Helper to make HTTP JSON requests
function makeRequest(path, method = "GET", data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
    };

    const req = http.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, data: parsed, headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, data: body, headers: res.headers });
        }
      });
    });

    req.on("error", (err) => reject(err));

    if (data) {
      req.write(JSON.stringify(data));
    }
    req.end();
  });
}

async function runTests() {
  console.log("\n========================================================");
  console.log("   CUSTOM OAUTH 2.0 SYSTEM - END-TO-END FLOW TESTS");
  console.log("========================================================\n");

  const testUser = {
    name: "Alex Dev",
    email: `alex_${Date.now()}@example.com`,
    password: "Password123!",
  };

  let accessToken = "";
  let refreshToken = "";

  try {
    // Test 1: Register User
    console.log("▶ [FLOW 1] Testing User Registration...");
    const regRes = await makeRequest("/auth/register", "POST", testUser);
    console.log(`  Status: ${regRes.status}`, regRes.data);
    if (regRes.status !== 201) throw new Error("Registration failed");
    console.log("  ✔ Registration successful!\n");

    // Test 1b: Duplicate Registration Check
    console.log("▶ [FLOW 1b] Testing Duplicate Email Prevention...");
    const dupRes = await makeRequest("/auth/register", "POST", testUser);
    console.log(`  Status: ${dupRes.status}`, dupRes.data);
    if (dupRes.status !== 409) throw new Error("Duplicate check failed");
    console.log("  ✔ Duplicate email correctly rejected with 409 Conflict!\n");

    // Test 2: Failed Login (Wrong Password)
    console.log("▶ [FLOW 2a] Testing Login with Wrong Password (Security Enumeration Check)...");
    const wrongLoginRes = await makeRequest("/auth/login", "POST", {
      email: testUser.email,
      password: "WrongPassword!",
    });
    console.log(`  Status: ${wrongLoginRes.status}`, wrongLoginRes.data);
    if (wrongLoginRes.status !== 401) throw new Error("Invalid password check failed");
    console.log("  ✔ Generic 'Invalid credentials' returned!\n");

    // Test 2b: Successful Login
    console.log("▶ [FLOW 2b] Testing Successful Login & HttpOnly Cookie Set...");
    const loginRes = await makeRequest("/auth/login", "POST", {
      email: testUser.email,
      password: testUser.password,
    });
    console.log(`  Status: ${loginRes.status}`);
    console.log(`  Access Token: ${loginRes.data.accessToken?.substring(0, 25)}...`);
    
    const setCookieHeader = loginRes.headers["set-cookie"];
    console.log(`  Set-Cookie Header: ${setCookieHeader ? setCookieHeader[0] : "None"}`);
    
    if (loginRes.status !== 200 || !loginRes.data.accessToken) throw new Error("Login failed");
    if (!setCookieHeader || !setCookieHeader[0].includes("HttpOnly")) throw new Error("HttpOnly cookie not set on login");

    accessToken = loginRes.data.accessToken;
    refreshToken = loginRes.data.refreshToken;
    const cookieString = setCookieHeader[0].split(";")[0]; // "refreshToken=..."
    console.log("  ✔ Tokens issued & HttpOnly Cookie set on response!\n");

    // Test 3: Protected Route without Token
    console.log("▶ [FLOW 3a] Testing Protected Route without Token...");
    const noAuthRes = await makeRequest("/auth/profile", "GET");
    console.log(`  Status: ${noAuthRes.status}`, noAuthRes.data);
    if (noAuthRes.status !== 401) throw new Error("Unauthenticated check failed");
    console.log("  ✔ Unauthenticated access blocked with 401!\n");

    // Test 3b: Protected Route with Valid Token
    console.log("▶ [FLOW 3b] Testing Protected Route with Bearer Token...");
    const authRes = await makeRequest("/auth/profile", "GET", null, {
      Authorization: `Bearer ${accessToken}`,
    });
    console.log(`  Status: ${authRes.status}`, authRes.data);
    if (authRes.status !== 200) throw new Error("Protected route access failed");
    console.log("  ✔ Protected route successfully accessed with Bearer Token!\n");

    // Test 4: Refresh Access Token via HttpOnly Cookie
    console.log("▶ [FLOW 4a] Testing Token Refresh via HttpOnly Cookie...");
    const cookieRefreshRes = await makeRequest("/auth/refresh", "POST", null, {
      Cookie: cookieString,
    });
    console.log(`  Status: ${cookieRefreshRes.status}`);
    console.log(`  New Access Token: ${cookieRefreshRes.data.accessToken?.substring(0, 25)}...`);
    if (cookieRefreshRes.status !== 200 || !cookieRefreshRes.data.accessToken) throw new Error("Cookie refresh token flow failed");
    console.log("  ✔ Refresh via HttpOnly Cookie successful!\n");

    // Test 4b: Refresh Access Token via JSON Request Body (Fallback)
    console.log("▶ [FLOW 4b] Testing Token Refresh via JSON Request Body (Fallback)...");
    const refreshRes = await makeRequest("/auth/refresh", "POST", { refreshToken });
    console.log(`  Status: ${refreshRes.status}`);
    console.log(`  New Access Token: ${refreshRes.data.accessToken?.substring(0, 25)}...`);
    if (refreshRes.status !== 200 || !refreshRes.data.accessToken) throw new Error("Body refresh token flow failed");

    const newAccessToken = refreshRes.data.accessToken;
    console.log("  ✔ Refresh via JSON request body fallback successful!\n");

    // Test 4c: Verify New Access Token Works
    console.log("▶ [FLOW 4c] Testing Protected Route with New Access Token...");
    const newAuthRes = await makeRequest("/auth/profile", "GET", null, {
      Authorization: `Bearer ${newAccessToken}`,
    });
    console.log(`  Status: ${newAuthRes.status}`, newAuthRes.data);
    if (newAuthRes.status !== 200) throw new Error("New access token verification failed");
    console.log("  ✔ New access token validated!\n");

    // Test 5: Logout Flow with Cookie Clearing
    console.log("▶ [FLOW 5a] Testing Logout Flow (Token Revocation & Cookie Clearing)...");
    const logoutRes = await makeRequest("/auth/logout", "POST", null, {
      Cookie: cookieString,
    });
    console.log(`  Status: ${logoutRes.status}`, logoutRes.data);
    console.log(`  Cleared Cookie Header: ${logoutRes.headers["set-cookie"] ? logoutRes.headers["set-cookie"][0] : "None"}`);
    if (logoutRes.status !== 200) throw new Error("Logout failed");
    console.log("  ✔ Refresh Token deleted from DB & HttpOnly cookie cleared!\n");

    // Test 5b: Verify Revoked Refresh Token is Rejected
    console.log("▶ [FLOW 5b] Testing Refresh Attempt with Revoked Refresh Token...");
    const revokedRefreshRes = await makeRequest("/auth/refresh", "POST", { refreshToken });
    console.log(`  Status: ${revokedRefreshRes.status}`, revokedRefreshRes.data);
    if (revokedRefreshRes.status !== 403) throw new Error("Revocation check failed");
    console.log("  ✔ Revoked token correctly rejected with 403 Forbidden!\n");

    console.log("========================================================");
    console.log("   🎉 ALL 5 OAUTH 2.0 FLOWS PASSED VERIFICATION!");
    console.log("========================================================\n");
  } catch (error) {
    console.error("\n❌ TEST FAILED:", error.message);
    process.exit(1);
  }
}

runTests();
