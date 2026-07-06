/*
 * INTENTIONALLY VULNERABLE TEST FIXTURE
 * Purpose: SAST/load testing only. Do NOT deploy, compile into an application, or run in production.
 * Notes:
 * - SAST tools usually report CWEs/query findings, not CVEs. CVEs are typically tied to vulnerable dependencies/SCA.
 * - This file creates 1000 synthetic source-code vulnerability patterns for scanner stress testing.
 */
//pr5
import java.io.*;
import java.sql.*;
import java.util.*;

public class CheckmarxSastLoadTest1000 {
    // Minimal stubs so the file is self-contained for static analysis.
    static class Request {
        String getParameter(String name) { return System.getProperty(name, "user_input"); }
        String getHeader(String name) { return System.getProperty(name, "header_input"); }
    }

    static class Response {
        void write(String value) { System.out.println(value); }
        void sendRedirect(String value) { System.out.println(value); }
        void addHeader(String name, String value) { System.out.println(name + value); }
    }

    static class Db {
        Statement createStatement() { return null; }
        PreparedStatement prepareStatement(String sql) { return null; }
    }

    private final Request request = new Request();
    private final Response response = new Response();
    private final Db db = new Db();

    private String source(int i) {
        return request.getParameter("p" + i);
    }

    private String header(int i) {
        return request.getHeader("h" + i);
    }

    private void sink(Object o) {
        System.out.println(o);
    }


    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0000_sqlInjection() throws Exception {
        String user = source(0);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0001_commandInjection() throws Exception {
        String cmd = source(1);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0002_pathTraversal() throws Exception {
        String fileName = source(2);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0003_reflectedOutput() {
        String value = source(3);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0004_openRedirect() {
        String next = source(4);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0005_hardcodedSecret() {
        String password = "Password123!_DoNotUse_5";
        String apiKey = "AKIA_TEST_ONLY_0005_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0006_headerInjection() {
        String headerValue = header(6);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0007_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0008_weakHash() {
        String input = source(8);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0009_sensitiveLog() {
        String token = source(9);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0010_sqlInjection() throws Exception {
        String user = source(10);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0011_commandInjection() throws Exception {
        String cmd = source(11);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0012_pathTraversal() throws Exception {
        String fileName = source(12);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0013_reflectedOutput() {
        String value = source(13);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0014_openRedirect() {
        String next = source(14);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0015_hardcodedSecret() {
        String password = "Password123!_DoNotUse_15";
        String apiKey = "AKIA_TEST_ONLY_0015_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0016_headerInjection() {
        String headerValue = header(16);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0017_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0018_weakHash() {
        String input = source(18);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0019_sensitiveLog() {
        String token = source(19);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0020_sqlInjection() throws Exception {
        String user = source(20);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0021_commandInjection() throws Exception {
        String cmd = source(21);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0022_pathTraversal() throws Exception {
        String fileName = source(22);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0023_reflectedOutput() {
        String value = source(23);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0024_openRedirect() {
        String next = source(24);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0025_hardcodedSecret() {
        String password = "Password123!_DoNotUse_25";
        String apiKey = "AKIA_TEST_ONLY_0025_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0026_headerInjection() {
        String headerValue = header(26);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0027_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0028_weakHash() {
        String input = source(28);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0029_sensitiveLog() {
        String token = source(29);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0030_sqlInjection() throws Exception {
        String user = source(30);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0031_commandInjection() throws Exception {
        String cmd = source(31);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0032_pathTraversal() throws Exception {
        String fileName = source(32);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0033_reflectedOutput() {
        String value = source(33);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0034_openRedirect() {
        String next = source(34);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0035_hardcodedSecret() {
        String password = "Password123!_DoNotUse_35";
        String apiKey = "AKIA_TEST_ONLY_0035_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0036_headerInjection() {
        String headerValue = header(36);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0037_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0038_weakHash() {
        String input = source(38);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0039_sensitiveLog() {
        String token = source(39);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0040_sqlInjection() throws Exception {
        String user = source(40);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0041_commandInjection() throws Exception {
        String cmd = source(41);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0042_pathTraversal() throws Exception {
        String fileName = source(42);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0043_reflectedOutput() {
        String value = source(43);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0044_openRedirect() {
        String next = source(44);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0045_hardcodedSecret() {
        String password = "Password123!_DoNotUse_45";
        String apiKey = "AKIA_TEST_ONLY_0045_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0046_headerInjection() {
        String headerValue = header(46);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0047_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0048_weakHash() {
        String input = source(48);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0049_sensitiveLog() {
        String token = source(49);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0050_sqlInjection() throws Exception {
        String user = source(50);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0051_commandInjection() throws Exception {
        String cmd = source(51);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0052_pathTraversal() throws Exception {
        String fileName = source(52);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0053_reflectedOutput() {
        String value = source(53);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0054_openRedirect() {
        String next = source(54);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0055_hardcodedSecret() {
        String password = "Password123!_DoNotUse_55";
        String apiKey = "AKIA_TEST_ONLY_0055_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0056_headerInjection() {
        String headerValue = header(56);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0057_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0058_weakHash() {
        String input = source(58);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0059_sensitiveLog() {
        String token = source(59);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0060_sqlInjection() throws Exception {
        String user = source(60);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0061_commandInjection() throws Exception {
        String cmd = source(61);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0062_pathTraversal() throws Exception {
        String fileName = source(62);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0063_reflectedOutput() {
        String value = source(63);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0064_openRedirect() {
        String next = source(64);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0065_hardcodedSecret() {
        String password = "Password123!_DoNotUse_65";
        String apiKey = "AKIA_TEST_ONLY_0065_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0066_headerInjection() {
        String headerValue = header(66);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0067_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0068_weakHash() {
        String input = source(68);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0069_sensitiveLog() {
        String token = source(69);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0070_sqlInjection() throws Exception {
        String user = source(70);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0071_commandInjection() throws Exception {
        String cmd = source(71);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0072_pathTraversal() throws Exception {
        String fileName = source(72);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0073_reflectedOutput() {
        String value = source(73);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0074_openRedirect() {
        String next = source(74);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0075_hardcodedSecret() {
        String password = "Password123!_DoNotUse_75";
        String apiKey = "AKIA_TEST_ONLY_0075_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0076_headerInjection() {
        String headerValue = header(76);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0077_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0078_weakHash() {
        String input = source(78);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0079_sensitiveLog() {
        String token = source(79);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0080_sqlInjection() throws Exception {
        String user = source(80);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0081_commandInjection() throws Exception {
        String cmd = source(81);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0082_pathTraversal() throws Exception {
        String fileName = source(82);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0083_reflectedOutput() {
        String value = source(83);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0084_openRedirect() {
        String next = source(84);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0085_hardcodedSecret() {
        String password = "Password123!_DoNotUse_85";
        String apiKey = "AKIA_TEST_ONLY_0085_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0086_headerInjection() {
        String headerValue = header(86);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0087_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0088_weakHash() {
        String input = source(88);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0089_sensitiveLog() {
        String token = source(89);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0090_sqlInjection() throws Exception {
        String user = source(90);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0091_commandInjection() throws Exception {
        String cmd = source(91);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0092_pathTraversal() throws Exception {
        String fileName = source(92);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0093_reflectedOutput() {
        String value = source(93);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0094_openRedirect() {
        String next = source(94);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0095_hardcodedSecret() {
        String password = "Password123!_DoNotUse_95";
        String apiKey = "AKIA_TEST_ONLY_0095_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0096_headerInjection() {
        String headerValue = header(96);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0097_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0098_weakHash() {
        String input = source(98);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0099_sensitiveLog() {
        String token = source(99);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0100_sqlInjection() throws Exception {
        String user = source(100);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0101_commandInjection() throws Exception {
        String cmd = source(101);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0102_pathTraversal() throws Exception {
        String fileName = source(102);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0103_reflectedOutput() {
        String value = source(103);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0104_openRedirect() {
        String next = source(104);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0105_hardcodedSecret() {
        String password = "Password123!_DoNotUse_105";
        String apiKey = "AKIA_TEST_ONLY_0105_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0106_headerInjection() {
        String headerValue = header(106);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0107_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0108_weakHash() {
        String input = source(108);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0109_sensitiveLog() {
        String token = source(109);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0110_sqlInjection() throws Exception {
        String user = source(110);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0111_commandInjection() throws Exception {
        String cmd = source(111);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0112_pathTraversal() throws Exception {
        String fileName = source(112);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0113_reflectedOutput() {
        String value = source(113);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0114_openRedirect() {
        String next = source(114);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0115_hardcodedSecret() {
        String password = "Password123!_DoNotUse_115";
        String apiKey = "AKIA_TEST_ONLY_0115_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0116_headerInjection() {
        String headerValue = header(116);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0117_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0118_weakHash() {
        String input = source(118);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0119_sensitiveLog() {
        String token = source(119);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0120_sqlInjection() throws Exception {
        String user = source(120);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0121_commandInjection() throws Exception {
        String cmd = source(121);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0122_pathTraversal() throws Exception {
        String fileName = source(122);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0123_reflectedOutput() {
        String value = source(123);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0124_openRedirect() {
        String next = source(124);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0125_hardcodedSecret() {
        String password = "Password123!_DoNotUse_125";
        String apiKey = "AKIA_TEST_ONLY_0125_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0126_headerInjection() {
        String headerValue = header(126);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0127_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0128_weakHash() {
        String input = source(128);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0129_sensitiveLog() {
        String token = source(129);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0130_sqlInjection() throws Exception {
        String user = source(130);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0131_commandInjection() throws Exception {
        String cmd = source(131);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0132_pathTraversal() throws Exception {
        String fileName = source(132);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0133_reflectedOutput() {
        String value = source(133);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0134_openRedirect() {
        String next = source(134);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0135_hardcodedSecret() {
        String password = "Password123!_DoNotUse_135";
        String apiKey = "AKIA_TEST_ONLY_0135_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0136_headerInjection() {
        String headerValue = header(136);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0137_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0138_weakHash() {
        String input = source(138);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0139_sensitiveLog() {
        String token = source(139);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0140_sqlInjection() throws Exception {
        String user = source(140);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0141_commandInjection() throws Exception {
        String cmd = source(141);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0142_pathTraversal() throws Exception {
        String fileName = source(142);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0143_reflectedOutput() {
        String value = source(143);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0144_openRedirect() {
        String next = source(144);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0145_hardcodedSecret() {
        String password = "Password123!_DoNotUse_145";
        String apiKey = "AKIA_TEST_ONLY_0145_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0146_headerInjection() {
        String headerValue = header(146);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0147_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0148_weakHash() {
        String input = source(148);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0149_sensitiveLog() {
        String token = source(149);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0150_sqlInjection() throws Exception {
        String user = source(150);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0151_commandInjection() throws Exception {
        String cmd = source(151);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0152_pathTraversal() throws Exception {
        String fileName = source(152);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0153_reflectedOutput() {
        String value = source(153);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0154_openRedirect() {
        String next = source(154);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0155_hardcodedSecret() {
        String password = "Password123!_DoNotUse_155";
        String apiKey = "AKIA_TEST_ONLY_0155_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0156_headerInjection() {
        String headerValue = header(156);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0157_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0158_weakHash() {
        String input = source(158);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0159_sensitiveLog() {
        String token = source(159);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0160_sqlInjection() throws Exception {
        String user = source(160);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0161_commandInjection() throws Exception {
        String cmd = source(161);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0162_pathTraversal() throws Exception {
        String fileName = source(162);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0163_reflectedOutput() {
        String value = source(163);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0164_openRedirect() {
        String next = source(164);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0165_hardcodedSecret() {
        String password = "Password123!_DoNotUse_165";
        String apiKey = "AKIA_TEST_ONLY_0165_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0166_headerInjection() {
        String headerValue = header(166);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0167_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0168_weakHash() {
        String input = source(168);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0169_sensitiveLog() {
        String token = source(169);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0170_sqlInjection() throws Exception {
        String user = source(170);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0171_commandInjection() throws Exception {
        String cmd = source(171);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0172_pathTraversal() throws Exception {
        String fileName = source(172);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0173_reflectedOutput() {
        String value = source(173);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0174_openRedirect() {
        String next = source(174);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0175_hardcodedSecret() {
        String password = "Password123!_DoNotUse_175";
        String apiKey = "AKIA_TEST_ONLY_0175_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0176_headerInjection() {
        String headerValue = header(176);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0177_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0178_weakHash() {
        String input = source(178);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0179_sensitiveLog() {
        String token = source(179);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0180_sqlInjection() throws Exception {
        String user = source(180);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0181_commandInjection() throws Exception {
        String cmd = source(181);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0182_pathTraversal() throws Exception {
        String fileName = source(182);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0183_reflectedOutput() {
        String value = source(183);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0184_openRedirect() {
        String next = source(184);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0185_hardcodedSecret() {
        String password = "Password123!_DoNotUse_185";
        String apiKey = "AKIA_TEST_ONLY_0185_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0186_headerInjection() {
        String headerValue = header(186);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0187_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0188_weakHash() {
        String input = source(188);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0189_sensitiveLog() {
        String token = source(189);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0190_sqlInjection() throws Exception {
        String user = source(190);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0191_commandInjection() throws Exception {
        String cmd = source(191);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0192_pathTraversal() throws Exception {
        String fileName = source(192);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0193_reflectedOutput() {
        String value = source(193);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0194_openRedirect() {
        String next = source(194);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0195_hardcodedSecret() {
        String password = "Password123!_DoNotUse_195";
        String apiKey = "AKIA_TEST_ONLY_0195_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0196_headerInjection() {
        String headerValue = header(196);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0197_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0198_weakHash() {
        String input = source(198);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0199_sensitiveLog() {
        String token = source(199);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0200_sqlInjection() throws Exception {
        String user = source(200);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0201_commandInjection() throws Exception {
        String cmd = source(201);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0202_pathTraversal() throws Exception {
        String fileName = source(202);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0203_reflectedOutput() {
        String value = source(203);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0204_openRedirect() {
        String next = source(204);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0205_hardcodedSecret() {
        String password = "Password123!_DoNotUse_205";
        String apiKey = "AKIA_TEST_ONLY_0205_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0206_headerInjection() {
        String headerValue = header(206);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0207_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0208_weakHash() {
        String input = source(208);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0209_sensitiveLog() {
        String token = source(209);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0210_sqlInjection() throws Exception {
        String user = source(210);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0211_commandInjection() throws Exception {
        String cmd = source(211);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0212_pathTraversal() throws Exception {
        String fileName = source(212);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0213_reflectedOutput() {
        String value = source(213);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0214_openRedirect() {
        String next = source(214);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0215_hardcodedSecret() {
        String password = "Password123!_DoNotUse_215";
        String apiKey = "AKIA_TEST_ONLY_0215_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0216_headerInjection() {
        String headerValue = header(216);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0217_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0218_weakHash() {
        String input = source(218);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0219_sensitiveLog() {
        String token = source(219);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0220_sqlInjection() throws Exception {
        String user = source(220);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0221_commandInjection() throws Exception {
        String cmd = source(221);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0222_pathTraversal() throws Exception {
        String fileName = source(222);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0223_reflectedOutput() {
        String value = source(223);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0224_openRedirect() {
        String next = source(224);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0225_hardcodedSecret() {
        String password = "Password123!_DoNotUse_225";
        String apiKey = "AKIA_TEST_ONLY_0225_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0226_headerInjection() {
        String headerValue = header(226);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0227_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0228_weakHash() {
        String input = source(228);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0229_sensitiveLog() {
        String token = source(229);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0230_sqlInjection() throws Exception {
        String user = source(230);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0231_commandInjection() throws Exception {
        String cmd = source(231);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0232_pathTraversal() throws Exception {
        String fileName = source(232);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0233_reflectedOutput() {
        String value = source(233);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0234_openRedirect() {
        String next = source(234);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0235_hardcodedSecret() {
        String password = "Password123!_DoNotUse_235";
        String apiKey = "AKIA_TEST_ONLY_0235_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0236_headerInjection() {
        String headerValue = header(236);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0237_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0238_weakHash() {
        String input = source(238);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0239_sensitiveLog() {
        String token = source(239);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0240_sqlInjection() throws Exception {
        String user = source(240);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0241_commandInjection() throws Exception {
        String cmd = source(241);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0242_pathTraversal() throws Exception {
        String fileName = source(242);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0243_reflectedOutput() {
        String value = source(243);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0244_openRedirect() {
        String next = source(244);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0245_hardcodedSecret() {
        String password = "Password123!_DoNotUse_245";
        String apiKey = "AKIA_TEST_ONLY_0245_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0246_headerInjection() {
        String headerValue = header(246);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0247_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0248_weakHash() {
        String input = source(248);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0249_sensitiveLog() {
        String token = source(249);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0250_sqlInjection() throws Exception {
        String user = source(250);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0251_commandInjection() throws Exception {
        String cmd = source(251);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0252_pathTraversal() throws Exception {
        String fileName = source(252);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0253_reflectedOutput() {
        String value = source(253);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0254_openRedirect() {
        String next = source(254);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0255_hardcodedSecret() {
        String password = "Password123!_DoNotUse_255";
        String apiKey = "AKIA_TEST_ONLY_0255_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0256_headerInjection() {
        String headerValue = header(256);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0257_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0258_weakHash() {
        String input = source(258);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0259_sensitiveLog() {
        String token = source(259);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0260_sqlInjection() throws Exception {
        String user = source(260);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0261_commandInjection() throws Exception {
        String cmd = source(261);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0262_pathTraversal() throws Exception {
        String fileName = source(262);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0263_reflectedOutput() {
        String value = source(263);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0264_openRedirect() {
        String next = source(264);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0265_hardcodedSecret() {
        String password = "Password123!_DoNotUse_265";
        String apiKey = "AKIA_TEST_ONLY_0265_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0266_headerInjection() {
        String headerValue = header(266);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0267_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0268_weakHash() {
        String input = source(268);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0269_sensitiveLog() {
        String token = source(269);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0270_sqlInjection() throws Exception {
        String user = source(270);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0271_commandInjection() throws Exception {
        String cmd = source(271);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0272_pathTraversal() throws Exception {
        String fileName = source(272);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0273_reflectedOutput() {
        String value = source(273);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0274_openRedirect() {
        String next = source(274);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0275_hardcodedSecret() {
        String password = "Password123!_DoNotUse_275";
        String apiKey = "AKIA_TEST_ONLY_0275_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0276_headerInjection() {
        String headerValue = header(276);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0277_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0278_weakHash() {
        String input = source(278);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0279_sensitiveLog() {
        String token = source(279);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0280_sqlInjection() throws Exception {
        String user = source(280);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0281_commandInjection() throws Exception {
        String cmd = source(281);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0282_pathTraversal() throws Exception {
        String fileName = source(282);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0283_reflectedOutput() {
        String value = source(283);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0284_openRedirect() {
        String next = source(284);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0285_hardcodedSecret() {
        String password = "Password123!_DoNotUse_285";
        String apiKey = "AKIA_TEST_ONLY_0285_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0286_headerInjection() {
        String headerValue = header(286);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0287_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0288_weakHash() {
        String input = source(288);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0289_sensitiveLog() {
        String token = source(289);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0290_sqlInjection() throws Exception {
        String user = source(290);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0291_commandInjection() throws Exception {
        String cmd = source(291);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0292_pathTraversal() throws Exception {
        String fileName = source(292);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0293_reflectedOutput() {
        String value = source(293);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0294_openRedirect() {
        String next = source(294);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0295_hardcodedSecret() {
        String password = "Password123!_DoNotUse_295";
        String apiKey = "AKIA_TEST_ONLY_0295_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0296_headerInjection() {
        String headerValue = header(296);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0297_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0298_weakHash() {
        String input = source(298);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0299_sensitiveLog() {
        String token = source(299);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0300_sqlInjection() throws Exception {
        String user = source(300);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0301_commandInjection() throws Exception {
        String cmd = source(301);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0302_pathTraversal() throws Exception {
        String fileName = source(302);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0303_reflectedOutput() {
        String value = source(303);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0304_openRedirect() {
        String next = source(304);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0305_hardcodedSecret() {
        String password = "Password123!_DoNotUse_305";
        String apiKey = "AKIA_TEST_ONLY_0305_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0306_headerInjection() {
        String headerValue = header(306);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0307_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0308_weakHash() {
        String input = source(308);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0309_sensitiveLog() {
        String token = source(309);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0310_sqlInjection() throws Exception {
        String user = source(310);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0311_commandInjection() throws Exception {
        String cmd = source(311);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0312_pathTraversal() throws Exception {
        String fileName = source(312);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0313_reflectedOutput() {
        String value = source(313);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0314_openRedirect() {
        String next = source(314);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0315_hardcodedSecret() {
        String password = "Password123!_DoNotUse_315";
        String apiKey = "AKIA_TEST_ONLY_0315_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0316_headerInjection() {
        String headerValue = header(316);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0317_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0318_weakHash() {
        String input = source(318);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0319_sensitiveLog() {
        String token = source(319);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0320_sqlInjection() throws Exception {
        String user = source(320);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0321_commandInjection() throws Exception {
        String cmd = source(321);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0322_pathTraversal() throws Exception {
        String fileName = source(322);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0323_reflectedOutput() {
        String value = source(323);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0324_openRedirect() {
        String next = source(324);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0325_hardcodedSecret() {
        String password = "Password123!_DoNotUse_325";
        String apiKey = "AKIA_TEST_ONLY_0325_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0326_headerInjection() {
        String headerValue = header(326);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0327_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0328_weakHash() {
        String input = source(328);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0329_sensitiveLog() {
        String token = source(329);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0330_sqlInjection() throws Exception {
        String user = source(330);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0331_commandInjection() throws Exception {
        String cmd = source(331);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0332_pathTraversal() throws Exception {
        String fileName = source(332);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0333_reflectedOutput() {
        String value = source(333);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0334_openRedirect() {
        String next = source(334);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0335_hardcodedSecret() {
        String password = "Password123!_DoNotUse_335";
        String apiKey = "AKIA_TEST_ONLY_0335_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0336_headerInjection() {
        String headerValue = header(336);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0337_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0338_weakHash() {
        String input = source(338);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0339_sensitiveLog() {
        String token = source(339);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0340_sqlInjection() throws Exception {
        String user = source(340);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0341_commandInjection() throws Exception {
        String cmd = source(341);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0342_pathTraversal() throws Exception {
        String fileName = source(342);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0343_reflectedOutput() {
        String value = source(343);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0344_openRedirect() {
        String next = source(344);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0345_hardcodedSecret() {
        String password = "Password123!_DoNotUse_345";
        String apiKey = "AKIA_TEST_ONLY_0345_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0346_headerInjection() {
        String headerValue = header(346);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0347_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0348_weakHash() {
        String input = source(348);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0349_sensitiveLog() {
        String token = source(349);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0350_sqlInjection() throws Exception {
        String user = source(350);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0351_commandInjection() throws Exception {
        String cmd = source(351);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0352_pathTraversal() throws Exception {
        String fileName = source(352);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0353_reflectedOutput() {
        String value = source(353);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0354_openRedirect() {
        String next = source(354);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0355_hardcodedSecret() {
        String password = "Password123!_DoNotUse_355";
        String apiKey = "AKIA_TEST_ONLY_0355_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0356_headerInjection() {
        String headerValue = header(356);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0357_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0358_weakHash() {
        String input = source(358);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0359_sensitiveLog() {
        String token = source(359);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0360_sqlInjection() throws Exception {
        String user = source(360);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0361_commandInjection() throws Exception {
        String cmd = source(361);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0362_pathTraversal() throws Exception {
        String fileName = source(362);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0363_reflectedOutput() {
        String value = source(363);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0364_openRedirect() {
        String next = source(364);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0365_hardcodedSecret() {
        String password = "Password123!_DoNotUse_365";
        String apiKey = "AKIA_TEST_ONLY_0365_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0366_headerInjection() {
        String headerValue = header(366);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0367_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0368_weakHash() {
        String input = source(368);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0369_sensitiveLog() {
        String token = source(369);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0370_sqlInjection() throws Exception {
        String user = source(370);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0371_commandInjection() throws Exception {
        String cmd = source(371);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0372_pathTraversal() throws Exception {
        String fileName = source(372);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0373_reflectedOutput() {
        String value = source(373);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0374_openRedirect() {
        String next = source(374);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0375_hardcodedSecret() {
        String password = "Password123!_DoNotUse_375";
        String apiKey = "AKIA_TEST_ONLY_0375_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0376_headerInjection() {
        String headerValue = header(376);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0377_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0378_weakHash() {
        String input = source(378);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0379_sensitiveLog() {
        String token = source(379);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0380_sqlInjection() throws Exception {
        String user = source(380);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0381_commandInjection() throws Exception {
        String cmd = source(381);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0382_pathTraversal() throws Exception {
        String fileName = source(382);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0383_reflectedOutput() {
        String value = source(383);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0384_openRedirect() {
        String next = source(384);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0385_hardcodedSecret() {
        String password = "Password123!_DoNotUse_385";
        String apiKey = "AKIA_TEST_ONLY_0385_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0386_headerInjection() {
        String headerValue = header(386);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0387_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0388_weakHash() {
        String input = source(388);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0389_sensitiveLog() {
        String token = source(389);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0390_sqlInjection() throws Exception {
        String user = source(390);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0391_commandInjection() throws Exception {
        String cmd = source(391);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0392_pathTraversal() throws Exception {
        String fileName = source(392);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0393_reflectedOutput() {
        String value = source(393);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0394_openRedirect() {
        String next = source(394);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0395_hardcodedSecret() {
        String password = "Password123!_DoNotUse_395";
        String apiKey = "AKIA_TEST_ONLY_0395_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0396_headerInjection() {
        String headerValue = header(396);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0397_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0398_weakHash() {
        String input = source(398);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0399_sensitiveLog() {
        String token = source(399);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0400_sqlInjection() throws Exception {
        String user = source(400);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0401_commandInjection() throws Exception {
        String cmd = source(401);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0402_pathTraversal() throws Exception {
        String fileName = source(402);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0403_reflectedOutput() {
        String value = source(403);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0404_openRedirect() {
        String next = source(404);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0405_hardcodedSecret() {
        String password = "Password123!_DoNotUse_405";
        String apiKey = "AKIA_TEST_ONLY_0405_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0406_headerInjection() {
        String headerValue = header(406);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0407_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0408_weakHash() {
        String input = source(408);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0409_sensitiveLog() {
        String token = source(409);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0410_sqlInjection() throws Exception {
        String user = source(410);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0411_commandInjection() throws Exception {
        String cmd = source(411);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0412_pathTraversal() throws Exception {
        String fileName = source(412);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0413_reflectedOutput() {
        String value = source(413);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0414_openRedirect() {
        String next = source(414);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0415_hardcodedSecret() {
        String password = "Password123!_DoNotUse_415";
        String apiKey = "AKIA_TEST_ONLY_0415_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0416_headerInjection() {
        String headerValue = header(416);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0417_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0418_weakHash() {
        String input = source(418);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0419_sensitiveLog() {
        String token = source(419);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0420_sqlInjection() throws Exception {
        String user = source(420);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0421_commandInjection() throws Exception {
        String cmd = source(421);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0422_pathTraversal() throws Exception {
        String fileName = source(422);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0423_reflectedOutput() {
        String value = source(423);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0424_openRedirect() {
        String next = source(424);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0425_hardcodedSecret() {
        String password = "Password123!_DoNotUse_425";
        String apiKey = "AKIA_TEST_ONLY_0425_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0426_headerInjection() {
        String headerValue = header(426);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0427_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0428_weakHash() {
        String input = source(428);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0429_sensitiveLog() {
        String token = source(429);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0430_sqlInjection() throws Exception {
        String user = source(430);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0431_commandInjection() throws Exception {
        String cmd = source(431);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0432_pathTraversal() throws Exception {
        String fileName = source(432);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0433_reflectedOutput() {
        String value = source(433);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0434_openRedirect() {
        String next = source(434);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0435_hardcodedSecret() {
        String password = "Password123!_DoNotUse_435";
        String apiKey = "AKIA_TEST_ONLY_0435_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0436_headerInjection() {
        String headerValue = header(436);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0437_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0438_weakHash() {
        String input = source(438);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0439_sensitiveLog() {
        String token = source(439);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0440_sqlInjection() throws Exception {
        String user = source(440);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0441_commandInjection() throws Exception {
        String cmd = source(441);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0442_pathTraversal() throws Exception {
        String fileName = source(442);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0443_reflectedOutput() {
        String value = source(443);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0444_openRedirect() {
        String next = source(444);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0445_hardcodedSecret() {
        String password = "Password123!_DoNotUse_445";
        String apiKey = "AKIA_TEST_ONLY_0445_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0446_headerInjection() {
        String headerValue = header(446);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0447_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0448_weakHash() {
        String input = source(448);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0449_sensitiveLog() {
        String token = source(449);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0450_sqlInjection() throws Exception {
        String user = source(450);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0451_commandInjection() throws Exception {
        String cmd = source(451);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0452_pathTraversal() throws Exception {
        String fileName = source(452);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0453_reflectedOutput() {
        String value = source(453);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0454_openRedirect() {
        String next = source(454);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0455_hardcodedSecret() {
        String password = "Password123!_DoNotUse_455";
        String apiKey = "AKIA_TEST_ONLY_0455_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0456_headerInjection() {
        String headerValue = header(456);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0457_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0458_weakHash() {
        String input = source(458);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0459_sensitiveLog() {
        String token = source(459);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0460_sqlInjection() throws Exception {
        String user = source(460);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0461_commandInjection() throws Exception {
        String cmd = source(461);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0462_pathTraversal() throws Exception {
        String fileName = source(462);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0463_reflectedOutput() {
        String value = source(463);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0464_openRedirect() {
        String next = source(464);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0465_hardcodedSecret() {
        String password = "Password123!_DoNotUse_465";
        String apiKey = "AKIA_TEST_ONLY_0465_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0466_headerInjection() {
        String headerValue = header(466);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0467_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0468_weakHash() {
        String input = source(468);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0469_sensitiveLog() {
        String token = source(469);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0470_sqlInjection() throws Exception {
        String user = source(470);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0471_commandInjection() throws Exception {
        String cmd = source(471);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0472_pathTraversal() throws Exception {
        String fileName = source(472);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0473_reflectedOutput() {
        String value = source(473);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0474_openRedirect() {
        String next = source(474);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0475_hardcodedSecret() {
        String password = "Password123!_DoNotUse_475";
        String apiKey = "AKIA_TEST_ONLY_0475_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0476_headerInjection() {
        String headerValue = header(476);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0477_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0478_weakHash() {
        String input = source(478);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0479_sensitiveLog() {
        String token = source(479);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0480_sqlInjection() throws Exception {
        String user = source(480);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0481_commandInjection() throws Exception {
        String cmd = source(481);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0482_pathTraversal() throws Exception {
        String fileName = source(482);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0483_reflectedOutput() {
        String value = source(483);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0484_openRedirect() {
        String next = source(484);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0485_hardcodedSecret() {
        String password = "Password123!_DoNotUse_485";
        String apiKey = "AKIA_TEST_ONLY_0485_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0486_headerInjection() {
        String headerValue = header(486);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0487_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0488_weakHash() {
        String input = source(488);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0489_sensitiveLog() {
        String token = source(489);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0490_sqlInjection() throws Exception {
        String user = source(490);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0491_commandInjection() throws Exception {
        String cmd = source(491);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0492_pathTraversal() throws Exception {
        String fileName = source(492);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0493_reflectedOutput() {
        String value = source(493);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0494_openRedirect() {
        String next = source(494);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0495_hardcodedSecret() {
        String password = "Password123!_DoNotUse_495";
        String apiKey = "AKIA_TEST_ONLY_0495_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0496_headerInjection() {
        String headerValue = header(496);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0497_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0498_weakHash() {
        String input = source(498);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0499_sensitiveLog() {
        String token = source(499);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0500_sqlInjection() throws Exception {
        String user = source(500);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0501_commandInjection() throws Exception {
        String cmd = source(501);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0502_pathTraversal() throws Exception {
        String fileName = source(502);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0503_reflectedOutput() {
        String value = source(503);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0504_openRedirect() {
        String next = source(504);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0505_hardcodedSecret() {
        String password = "Password123!_DoNotUse_505";
        String apiKey = "AKIA_TEST_ONLY_0505_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0506_headerInjection() {
        String headerValue = header(506);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0507_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0508_weakHash() {
        String input = source(508);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0509_sensitiveLog() {
        String token = source(509);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0510_sqlInjection() throws Exception {
        String user = source(510);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0511_commandInjection() throws Exception {
        String cmd = source(511);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0512_pathTraversal() throws Exception {
        String fileName = source(512);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0513_reflectedOutput() {
        String value = source(513);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0514_openRedirect() {
        String next = source(514);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0515_hardcodedSecret() {
        String password = "Password123!_DoNotUse_515";
        String apiKey = "AKIA_TEST_ONLY_0515_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0516_headerInjection() {
        String headerValue = header(516);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0517_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0518_weakHash() {
        String input = source(518);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0519_sensitiveLog() {
        String token = source(519);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0520_sqlInjection() throws Exception {
        String user = source(520);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0521_commandInjection() throws Exception {
        String cmd = source(521);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0522_pathTraversal() throws Exception {
        String fileName = source(522);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0523_reflectedOutput() {
        String value = source(523);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0524_openRedirect() {
        String next = source(524);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0525_hardcodedSecret() {
        String password = "Password123!_DoNotUse_525";
        String apiKey = "AKIA_TEST_ONLY_0525_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0526_headerInjection() {
        String headerValue = header(526);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0527_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0528_weakHash() {
        String input = source(528);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0529_sensitiveLog() {
        String token = source(529);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0530_sqlInjection() throws Exception {
        String user = source(530);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0531_commandInjection() throws Exception {
        String cmd = source(531);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0532_pathTraversal() throws Exception {
        String fileName = source(532);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0533_reflectedOutput() {
        String value = source(533);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0534_openRedirect() {
        String next = source(534);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0535_hardcodedSecret() {
        String password = "Password123!_DoNotUse_535";
        String apiKey = "AKIA_TEST_ONLY_0535_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0536_headerInjection() {
        String headerValue = header(536);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0537_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0538_weakHash() {
        String input = source(538);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0539_sensitiveLog() {
        String token = source(539);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0540_sqlInjection() throws Exception {
        String user = source(540);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0541_commandInjection() throws Exception {
        String cmd = source(541);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0542_pathTraversal() throws Exception {
        String fileName = source(542);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0543_reflectedOutput() {
        String value = source(543);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0544_openRedirect() {
        String next = source(544);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0545_hardcodedSecret() {
        String password = "Password123!_DoNotUse_545";
        String apiKey = "AKIA_TEST_ONLY_0545_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0546_headerInjection() {
        String headerValue = header(546);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0547_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0548_weakHash() {
        String input = source(548);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0549_sensitiveLog() {
        String token = source(549);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0550_sqlInjection() throws Exception {
        String user = source(550);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0551_commandInjection() throws Exception {
        String cmd = source(551);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0552_pathTraversal() throws Exception {
        String fileName = source(552);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0553_reflectedOutput() {
        String value = source(553);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0554_openRedirect() {
        String next = source(554);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0555_hardcodedSecret() {
        String password = "Password123!_DoNotUse_555";
        String apiKey = "AKIA_TEST_ONLY_0555_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0556_headerInjection() {
        String headerValue = header(556);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0557_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0558_weakHash() {
        String input = source(558);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0559_sensitiveLog() {
        String token = source(559);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0560_sqlInjection() throws Exception {
        String user = source(560);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0561_commandInjection() throws Exception {
        String cmd = source(561);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0562_pathTraversal() throws Exception {
        String fileName = source(562);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0563_reflectedOutput() {
        String value = source(563);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0564_openRedirect() {
        String next = source(564);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0565_hardcodedSecret() {
        String password = "Password123!_DoNotUse_565";
        String apiKey = "AKIA_TEST_ONLY_0565_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0566_headerInjection() {
        String headerValue = header(566);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0567_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0568_weakHash() {
        String input = source(568);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0569_sensitiveLog() {
        String token = source(569);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0570_sqlInjection() throws Exception {
        String user = source(570);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0571_commandInjection() throws Exception {
        String cmd = source(571);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0572_pathTraversal() throws Exception {
        String fileName = source(572);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0573_reflectedOutput() {
        String value = source(573);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0574_openRedirect() {
        String next = source(574);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0575_hardcodedSecret() {
        String password = "Password123!_DoNotUse_575";
        String apiKey = "AKIA_TEST_ONLY_0575_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0576_headerInjection() {
        String headerValue = header(576);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0577_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0578_weakHash() {
        String input = source(578);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0579_sensitiveLog() {
        String token = source(579);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0580_sqlInjection() throws Exception {
        String user = source(580);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0581_commandInjection() throws Exception {
        String cmd = source(581);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0582_pathTraversal() throws Exception {
        String fileName = source(582);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0583_reflectedOutput() {
        String value = source(583);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0584_openRedirect() {
        String next = source(584);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0585_hardcodedSecret() {
        String password = "Password123!_DoNotUse_585";
        String apiKey = "AKIA_TEST_ONLY_0585_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0586_headerInjection() {
        String headerValue = header(586);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0587_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0588_weakHash() {
        String input = source(588);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0589_sensitiveLog() {
        String token = source(589);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0590_sqlInjection() throws Exception {
        String user = source(590);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0591_commandInjection() throws Exception {
        String cmd = source(591);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0592_pathTraversal() throws Exception {
        String fileName = source(592);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0593_reflectedOutput() {
        String value = source(593);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0594_openRedirect() {
        String next = source(594);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0595_hardcodedSecret() {
        String password = "Password123!_DoNotUse_595";
        String apiKey = "AKIA_TEST_ONLY_0595_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0596_headerInjection() {
        String headerValue = header(596);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0597_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0598_weakHash() {
        String input = source(598);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0599_sensitiveLog() {
        String token = source(599);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0600_sqlInjection() throws Exception {
        String user = source(600);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0601_commandInjection() throws Exception {
        String cmd = source(601);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0602_pathTraversal() throws Exception {
        String fileName = source(602);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0603_reflectedOutput() {
        String value = source(603);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0604_openRedirect() {
        String next = source(604);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0605_hardcodedSecret() {
        String password = "Password123!_DoNotUse_605";
        String apiKey = "AKIA_TEST_ONLY_0605_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0606_headerInjection() {
        String headerValue = header(606);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0607_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0608_weakHash() {
        String input = source(608);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0609_sensitiveLog() {
        String token = source(609);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0610_sqlInjection() throws Exception {
        String user = source(610);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0611_commandInjection() throws Exception {
        String cmd = source(611);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0612_pathTraversal() throws Exception {
        String fileName = source(612);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0613_reflectedOutput() {
        String value = source(613);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0614_openRedirect() {
        String next = source(614);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0615_hardcodedSecret() {
        String password = "Password123!_DoNotUse_615";
        String apiKey = "AKIA_TEST_ONLY_0615_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0616_headerInjection() {
        String headerValue = header(616);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0617_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0618_weakHash() {
        String input = source(618);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0619_sensitiveLog() {
        String token = source(619);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0620_sqlInjection() throws Exception {
        String user = source(620);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0621_commandInjection() throws Exception {
        String cmd = source(621);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0622_pathTraversal() throws Exception {
        String fileName = source(622);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0623_reflectedOutput() {
        String value = source(623);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0624_openRedirect() {
        String next = source(624);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0625_hardcodedSecret() {
        String password = "Password123!_DoNotUse_625";
        String apiKey = "AKIA_TEST_ONLY_0625_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0626_headerInjection() {
        String headerValue = header(626);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0627_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0628_weakHash() {
        String input = source(628);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0629_sensitiveLog() {
        String token = source(629);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0630_sqlInjection() throws Exception {
        String user = source(630);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0631_commandInjection() throws Exception {
        String cmd = source(631);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0632_pathTraversal() throws Exception {
        String fileName = source(632);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0633_reflectedOutput() {
        String value = source(633);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0634_openRedirect() {
        String next = source(634);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0635_hardcodedSecret() {
        String password = "Password123!_DoNotUse_635";
        String apiKey = "AKIA_TEST_ONLY_0635_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0636_headerInjection() {
        String headerValue = header(636);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0637_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0638_weakHash() {
        String input = source(638);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0639_sensitiveLog() {
        String token = source(639);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0640_sqlInjection() throws Exception {
        String user = source(640);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0641_commandInjection() throws Exception {
        String cmd = source(641);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0642_pathTraversal() throws Exception {
        String fileName = source(642);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0643_reflectedOutput() {
        String value = source(643);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0644_openRedirect() {
        String next = source(644);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0645_hardcodedSecret() {
        String password = "Password123!_DoNotUse_645";
        String apiKey = "AKIA_TEST_ONLY_0645_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0646_headerInjection() {
        String headerValue = header(646);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0647_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0648_weakHash() {
        String input = source(648);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0649_sensitiveLog() {
        String token = source(649);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0650_sqlInjection() throws Exception {
        String user = source(650);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0651_commandInjection() throws Exception {
        String cmd = source(651);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0652_pathTraversal() throws Exception {
        String fileName = source(652);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0653_reflectedOutput() {
        String value = source(653);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0654_openRedirect() {
        String next = source(654);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0655_hardcodedSecret() {
        String password = "Password123!_DoNotUse_655";
        String apiKey = "AKIA_TEST_ONLY_0655_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0656_headerInjection() {
        String headerValue = header(656);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0657_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0658_weakHash() {
        String input = source(658);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0659_sensitiveLog() {
        String token = source(659);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0660_sqlInjection() throws Exception {
        String user = source(660);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0661_commandInjection() throws Exception {
        String cmd = source(661);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0662_pathTraversal() throws Exception {
        String fileName = source(662);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0663_reflectedOutput() {
        String value = source(663);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0664_openRedirect() {
        String next = source(664);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0665_hardcodedSecret() {
        String password = "Password123!_DoNotUse_665";
        String apiKey = "AKIA_TEST_ONLY_0665_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0666_headerInjection() {
        String headerValue = header(666);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0667_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0668_weakHash() {
        String input = source(668);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0669_sensitiveLog() {
        String token = source(669);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0670_sqlInjection() throws Exception {
        String user = source(670);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0671_commandInjection() throws Exception {
        String cmd = source(671);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0672_pathTraversal() throws Exception {
        String fileName = source(672);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0673_reflectedOutput() {
        String value = source(673);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0674_openRedirect() {
        String next = source(674);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0675_hardcodedSecret() {
        String password = "Password123!_DoNotUse_675";
        String apiKey = "AKIA_TEST_ONLY_0675_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0676_headerInjection() {
        String headerValue = header(676);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0677_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0678_weakHash() {
        String input = source(678);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0679_sensitiveLog() {
        String token = source(679);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0680_sqlInjection() throws Exception {
        String user = source(680);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0681_commandInjection() throws Exception {
        String cmd = source(681);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0682_pathTraversal() throws Exception {
        String fileName = source(682);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0683_reflectedOutput() {
        String value = source(683);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0684_openRedirect() {
        String next = source(684);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0685_hardcodedSecret() {
        String password = "Password123!_DoNotUse_685";
        String apiKey = "AKIA_TEST_ONLY_0685_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0686_headerInjection() {
        String headerValue = header(686);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0687_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0688_weakHash() {
        String input = source(688);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0689_sensitiveLog() {
        String token = source(689);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0690_sqlInjection() throws Exception {
        String user = source(690);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0691_commandInjection() throws Exception {
        String cmd = source(691);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0692_pathTraversal() throws Exception {
        String fileName = source(692);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0693_reflectedOutput() {
        String value = source(693);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0694_openRedirect() {
        String next = source(694);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0695_hardcodedSecret() {
        String password = "Password123!_DoNotUse_695";
        String apiKey = "AKIA_TEST_ONLY_0695_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0696_headerInjection() {
        String headerValue = header(696);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0697_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0698_weakHash() {
        String input = source(698);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0699_sensitiveLog() {
        String token = source(699);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0700_sqlInjection() throws Exception {
        String user = source(700);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0701_commandInjection() throws Exception {
        String cmd = source(701);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0702_pathTraversal() throws Exception {
        String fileName = source(702);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0703_reflectedOutput() {
        String value = source(703);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0704_openRedirect() {
        String next = source(704);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0705_hardcodedSecret() {
        String password = "Password123!_DoNotUse_705";
        String apiKey = "AKIA_TEST_ONLY_0705_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0706_headerInjection() {
        String headerValue = header(706);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0707_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0708_weakHash() {
        String input = source(708);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0709_sensitiveLog() {
        String token = source(709);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0710_sqlInjection() throws Exception {
        String user = source(710);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0711_commandInjection() throws Exception {
        String cmd = source(711);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0712_pathTraversal() throws Exception {
        String fileName = source(712);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0713_reflectedOutput() {
        String value = source(713);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0714_openRedirect() {
        String next = source(714);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0715_hardcodedSecret() {
        String password = "Password123!_DoNotUse_715";
        String apiKey = "AKIA_TEST_ONLY_0715_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0716_headerInjection() {
        String headerValue = header(716);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0717_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0718_weakHash() {
        String input = source(718);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0719_sensitiveLog() {
        String token = source(719);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0720_sqlInjection() throws Exception {
        String user = source(720);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0721_commandInjection() throws Exception {
        String cmd = source(721);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0722_pathTraversal() throws Exception {
        String fileName = source(722);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0723_reflectedOutput() {
        String value = source(723);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0724_openRedirect() {
        String next = source(724);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0725_hardcodedSecret() {
        String password = "Password123!_DoNotUse_725";
        String apiKey = "AKIA_TEST_ONLY_0725_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0726_headerInjection() {
        String headerValue = header(726);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0727_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0728_weakHash() {
        String input = source(728);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0729_sensitiveLog() {
        String token = source(729);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0730_sqlInjection() throws Exception {
        String user = source(730);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0731_commandInjection() throws Exception {
        String cmd = source(731);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0732_pathTraversal() throws Exception {
        String fileName = source(732);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0733_reflectedOutput() {
        String value = source(733);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0734_openRedirect() {
        String next = source(734);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0735_hardcodedSecret() {
        String password = "Password123!_DoNotUse_735";
        String apiKey = "AKIA_TEST_ONLY_0735_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0736_headerInjection() {
        String headerValue = header(736);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0737_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0738_weakHash() {
        String input = source(738);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0739_sensitiveLog() {
        String token = source(739);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0740_sqlInjection() throws Exception {
        String user = source(740);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0741_commandInjection() throws Exception {
        String cmd = source(741);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0742_pathTraversal() throws Exception {
        String fileName = source(742);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0743_reflectedOutput() {
        String value = source(743);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0744_openRedirect() {
        String next = source(744);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0745_hardcodedSecret() {
        String password = "Password123!_DoNotUse_745";
        String apiKey = "AKIA_TEST_ONLY_0745_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0746_headerInjection() {
        String headerValue = header(746);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0747_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0748_weakHash() {
        String input = source(748);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0749_sensitiveLog() {
        String token = source(749);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0750_sqlInjection() throws Exception {
        String user = source(750);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0751_commandInjection() throws Exception {
        String cmd = source(751);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0752_pathTraversal() throws Exception {
        String fileName = source(752);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0753_reflectedOutput() {
        String value = source(753);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0754_openRedirect() {
        String next = source(754);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0755_hardcodedSecret() {
        String password = "Password123!_DoNotUse_755";
        String apiKey = "AKIA_TEST_ONLY_0755_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0756_headerInjection() {
        String headerValue = header(756);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0757_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0758_weakHash() {
        String input = source(758);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0759_sensitiveLog() {
        String token = source(759);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0760_sqlInjection() throws Exception {
        String user = source(760);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0761_commandInjection() throws Exception {
        String cmd = source(761);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0762_pathTraversal() throws Exception {
        String fileName = source(762);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0763_reflectedOutput() {
        String value = source(763);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0764_openRedirect() {
        String next = source(764);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0765_hardcodedSecret() {
        String password = "Password123!_DoNotUse_765";
        String apiKey = "AKIA_TEST_ONLY_0765_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0766_headerInjection() {
        String headerValue = header(766);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0767_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0768_weakHash() {
        String input = source(768);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0769_sensitiveLog() {
        String token = source(769);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0770_sqlInjection() throws Exception {
        String user = source(770);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0771_commandInjection() throws Exception {
        String cmd = source(771);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0772_pathTraversal() throws Exception {
        String fileName = source(772);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0773_reflectedOutput() {
        String value = source(773);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0774_openRedirect() {
        String next = source(774);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0775_hardcodedSecret() {
        String password = "Password123!_DoNotUse_775";
        String apiKey = "AKIA_TEST_ONLY_0775_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0776_headerInjection() {
        String headerValue = header(776);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0777_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0778_weakHash() {
        String input = source(778);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0779_sensitiveLog() {
        String token = source(779);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0780_sqlInjection() throws Exception {
        String user = source(780);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0781_commandInjection() throws Exception {
        String cmd = source(781);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0782_pathTraversal() throws Exception {
        String fileName = source(782);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0783_reflectedOutput() {
        String value = source(783);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0784_openRedirect() {
        String next = source(784);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0785_hardcodedSecret() {
        String password = "Password123!_DoNotUse_785";
        String apiKey = "AKIA_TEST_ONLY_0785_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0786_headerInjection() {
        String headerValue = header(786);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0787_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0788_weakHash() {
        String input = source(788);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0789_sensitiveLog() {
        String token = source(789);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0790_sqlInjection() throws Exception {
        String user = source(790);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0791_commandInjection() throws Exception {
        String cmd = source(791);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0792_pathTraversal() throws Exception {
        String fileName = source(792);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0793_reflectedOutput() {
        String value = source(793);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0794_openRedirect() {
        String next = source(794);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0795_hardcodedSecret() {
        String password = "Password123!_DoNotUse_795";
        String apiKey = "AKIA_TEST_ONLY_0795_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0796_headerInjection() {
        String headerValue = header(796);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0797_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0798_weakHash() {
        String input = source(798);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0799_sensitiveLog() {
        String token = source(799);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0800_sqlInjection() throws Exception {
        String user = source(800);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0801_commandInjection() throws Exception {
        String cmd = source(801);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0802_pathTraversal() throws Exception {
        String fileName = source(802);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0803_reflectedOutput() {
        String value = source(803);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0804_openRedirect() {
        String next = source(804);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0805_hardcodedSecret() {
        String password = "Password123!_DoNotUse_805";
        String apiKey = "AKIA_TEST_ONLY_0805_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0806_headerInjection() {
        String headerValue = header(806);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0807_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0808_weakHash() {
        String input = source(808);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0809_sensitiveLog() {
        String token = source(809);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0810_sqlInjection() throws Exception {
        String user = source(810);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0811_commandInjection() throws Exception {
        String cmd = source(811);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0812_pathTraversal() throws Exception {
        String fileName = source(812);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0813_reflectedOutput() {
        String value = source(813);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0814_openRedirect() {
        String next = source(814);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0815_hardcodedSecret() {
        String password = "Password123!_DoNotUse_815";
        String apiKey = "AKIA_TEST_ONLY_0815_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0816_headerInjection() {
        String headerValue = header(816);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0817_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0818_weakHash() {
        String input = source(818);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0819_sensitiveLog() {
        String token = source(819);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0820_sqlInjection() throws Exception {
        String user = source(820);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0821_commandInjection() throws Exception {
        String cmd = source(821);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0822_pathTraversal() throws Exception {
        String fileName = source(822);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0823_reflectedOutput() {
        String value = source(823);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0824_openRedirect() {
        String next = source(824);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0825_hardcodedSecret() {
        String password = "Password123!_DoNotUse_825";
        String apiKey = "AKIA_TEST_ONLY_0825_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0826_headerInjection() {
        String headerValue = header(826);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0827_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0828_weakHash() {
        String input = source(828);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0829_sensitiveLog() {
        String token = source(829);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0830_sqlInjection() throws Exception {
        String user = source(830);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0831_commandInjection() throws Exception {
        String cmd = source(831);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0832_pathTraversal() throws Exception {
        String fileName = source(832);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0833_reflectedOutput() {
        String value = source(833);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0834_openRedirect() {
        String next = source(834);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0835_hardcodedSecret() {
        String password = "Password123!_DoNotUse_835";
        String apiKey = "AKIA_TEST_ONLY_0835_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0836_headerInjection() {
        String headerValue = header(836);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0837_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0838_weakHash() {
        String input = source(838);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0839_sensitiveLog() {
        String token = source(839);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0840_sqlInjection() throws Exception {
        String user = source(840);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0841_commandInjection() throws Exception {
        String cmd = source(841);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0842_pathTraversal() throws Exception {
        String fileName = source(842);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0843_reflectedOutput() {
        String value = source(843);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0844_openRedirect() {
        String next = source(844);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0845_hardcodedSecret() {
        String password = "Password123!_DoNotUse_845";
        String apiKey = "AKIA_TEST_ONLY_0845_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0846_headerInjection() {
        String headerValue = header(846);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0847_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0848_weakHash() {
        String input = source(848);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0849_sensitiveLog() {
        String token = source(849);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0850_sqlInjection() throws Exception {
        String user = source(850);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0851_commandInjection() throws Exception {
        String cmd = source(851);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0852_pathTraversal() throws Exception {
        String fileName = source(852);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0853_reflectedOutput() {
        String value = source(853);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0854_openRedirect() {
        String next = source(854);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0855_hardcodedSecret() {
        String password = "Password123!_DoNotUse_855";
        String apiKey = "AKIA_TEST_ONLY_0855_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0856_headerInjection() {
        String headerValue = header(856);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0857_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0858_weakHash() {
        String input = source(858);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0859_sensitiveLog() {
        String token = source(859);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0860_sqlInjection() throws Exception {
        String user = source(860);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0861_commandInjection() throws Exception {
        String cmd = source(861);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0862_pathTraversal() throws Exception {
        String fileName = source(862);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0863_reflectedOutput() {
        String value = source(863);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0864_openRedirect() {
        String next = source(864);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0865_hardcodedSecret() {
        String password = "Password123!_DoNotUse_865";
        String apiKey = "AKIA_TEST_ONLY_0865_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0866_headerInjection() {
        String headerValue = header(866);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0867_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0868_weakHash() {
        String input = source(868);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0869_sensitiveLog() {
        String token = source(869);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0870_sqlInjection() throws Exception {
        String user = source(870);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0871_commandInjection() throws Exception {
        String cmd = source(871);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0872_pathTraversal() throws Exception {
        String fileName = source(872);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0873_reflectedOutput() {
        String value = source(873);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0874_openRedirect() {
        String next = source(874);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0875_hardcodedSecret() {
        String password = "Password123!_DoNotUse_875";
        String apiKey = "AKIA_TEST_ONLY_0875_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0876_headerInjection() {
        String headerValue = header(876);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0877_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0878_weakHash() {
        String input = source(878);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0879_sensitiveLog() {
        String token = source(879);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0880_sqlInjection() throws Exception {
        String user = source(880);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0881_commandInjection() throws Exception {
        String cmd = source(881);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0882_pathTraversal() throws Exception {
        String fileName = source(882);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0883_reflectedOutput() {
        String value = source(883);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0884_openRedirect() {
        String next = source(884);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0885_hardcodedSecret() {
        String password = "Password123!_DoNotUse_885";
        String apiKey = "AKIA_TEST_ONLY_0885_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0886_headerInjection() {
        String headerValue = header(886);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0887_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0888_weakHash() {
        String input = source(888);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0889_sensitiveLog() {
        String token = source(889);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0890_sqlInjection() throws Exception {
        String user = source(890);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0891_commandInjection() throws Exception {
        String cmd = source(891);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0892_pathTraversal() throws Exception {
        String fileName = source(892);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0893_reflectedOutput() {
        String value = source(893);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0894_openRedirect() {
        String next = source(894);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0895_hardcodedSecret() {
        String password = "Password123!_DoNotUse_895";
        String apiKey = "AKIA_TEST_ONLY_0895_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0896_headerInjection() {
        String headerValue = header(896);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0897_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0898_weakHash() {
        String input = source(898);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0899_sensitiveLog() {
        String token = source(899);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0900_sqlInjection() throws Exception {
        String user = source(900);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0901_commandInjection() throws Exception {
        String cmd = source(901);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0902_pathTraversal() throws Exception {
        String fileName = source(902);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0903_reflectedOutput() {
        String value = source(903);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0904_openRedirect() {
        String next = source(904);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0905_hardcodedSecret() {
        String password = "Password123!_DoNotUse_905";
        String apiKey = "AKIA_TEST_ONLY_0905_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0906_headerInjection() {
        String headerValue = header(906);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0907_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0908_weakHash() {
        String input = source(908);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0909_sensitiveLog() {
        String token = source(909);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0910_sqlInjection() throws Exception {
        String user = source(910);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0911_commandInjection() throws Exception {
        String cmd = source(911);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0912_pathTraversal() throws Exception {
        String fileName = source(912);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0913_reflectedOutput() {
        String value = source(913);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0914_openRedirect() {
        String next = source(914);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0915_hardcodedSecret() {
        String password = "Password123!_DoNotUse_915";
        String apiKey = "AKIA_TEST_ONLY_0915_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0916_headerInjection() {
        String headerValue = header(916);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0917_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0918_weakHash() {
        String input = source(918);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0919_sensitiveLog() {
        String token = source(919);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0920_sqlInjection() throws Exception {
        String user = source(920);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0921_commandInjection() throws Exception {
        String cmd = source(921);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0922_pathTraversal() throws Exception {
        String fileName = source(922);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0923_reflectedOutput() {
        String value = source(923);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0924_openRedirect() {
        String next = source(924);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0925_hardcodedSecret() {
        String password = "Password123!_DoNotUse_925";
        String apiKey = "AKIA_TEST_ONLY_0925_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0926_headerInjection() {
        String headerValue = header(926);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0927_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0928_weakHash() {
        String input = source(928);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0929_sensitiveLog() {
        String token = source(929);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0930_sqlInjection() throws Exception {
        String user = source(930);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0931_commandInjection() throws Exception {
        String cmd = source(931);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0932_pathTraversal() throws Exception {
        String fileName = source(932);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0933_reflectedOutput() {
        String value = source(933);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0934_openRedirect() {
        String next = source(934);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0935_hardcodedSecret() {
        String password = "Password123!_DoNotUse_935";
        String apiKey = "AKIA_TEST_ONLY_0935_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0936_headerInjection() {
        String headerValue = header(936);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0937_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0938_weakHash() {
        String input = source(938);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0939_sensitiveLog() {
        String token = source(939);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0940_sqlInjection() throws Exception {
        String user = source(940);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0941_commandInjection() throws Exception {
        String cmd = source(941);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0942_pathTraversal() throws Exception {
        String fileName = source(942);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0943_reflectedOutput() {
        String value = source(943);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0944_openRedirect() {
        String next = source(944);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0945_hardcodedSecret() {
        String password = "Password123!_DoNotUse_945";
        String apiKey = "AKIA_TEST_ONLY_0945_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0946_headerInjection() {
        String headerValue = header(946);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0947_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0948_weakHash() {
        String input = source(948);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0949_sensitiveLog() {
        String token = source(949);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0950_sqlInjection() throws Exception {
        String user = source(950);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0951_commandInjection() throws Exception {
        String cmd = source(951);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0952_pathTraversal() throws Exception {
        String fileName = source(952);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0953_reflectedOutput() {
        String value = source(953);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0954_openRedirect() {
        String next = source(954);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0955_hardcodedSecret() {
        String password = "Password123!_DoNotUse_955";
        String apiKey = "AKIA_TEST_ONLY_0955_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0956_headerInjection() {
        String headerValue = header(956);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0957_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0958_weakHash() {
        String input = source(958);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0959_sensitiveLog() {
        String token = source(959);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0960_sqlInjection() throws Exception {
        String user = source(960);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0961_commandInjection() throws Exception {
        String cmd = source(961);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0962_pathTraversal() throws Exception {
        String fileName = source(962);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0963_reflectedOutput() {
        String value = source(963);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0964_openRedirect() {
        String next = source(964);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0965_hardcodedSecret() {
        String password = "Password123!_DoNotUse_965";
        String apiKey = "AKIA_TEST_ONLY_0965_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0966_headerInjection() {
        String headerValue = header(966);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0967_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0968_weakHash() {
        String input = source(968);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0969_sensitiveLog() {
        String token = source(969);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0970_sqlInjection() throws Exception {
        String user = source(970);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0971_commandInjection() throws Exception {
        String cmd = source(971);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0972_pathTraversal() throws Exception {
        String fileName = source(972);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0973_reflectedOutput() {
        String value = source(973);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0974_openRedirect() {
        String next = source(974);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0975_hardcodedSecret() {
        String password = "Password123!_DoNotUse_975";
        String apiKey = "AKIA_TEST_ONLY_0975_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0976_headerInjection() {
        String headerValue = header(976);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0977_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0978_weakHash() {
        String input = source(978);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0979_sensitiveLog() {
        String token = source(979);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0980_sqlInjection() throws Exception {
        String user = source(980);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0981_commandInjection() throws Exception {
        String cmd = source(981);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0982_pathTraversal() throws Exception {
        String fileName = source(982);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0983_reflectedOutput() {
        String value = source(983);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0984_openRedirect() {
        String next = source(984);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0985_hardcodedSecret() {
        String password = "Password123!_DoNotUse_985";
        String apiKey = "AKIA_TEST_ONLY_0985_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0986_headerInjection() {
        String headerValue = header(986);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0987_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0988_weakHash() {
        String input = source(988);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0989_sensitiveLog() {
        String token = source(989);
        System.out.println("user token=" + token);
    }

    // CWE-89 style: SQL injection via string concatenation
    public void vuln_0990_sqlInjection() throws Exception {
        String user = source(990);
        String query = "SELECT * FROM users WHERE name = '" + user + "'";
        Statement st = db.createStatement();
        if (st != null) st.executeQuery(query);
    }

    // CWE-78 style: OS command injection
    public void vuln_0991_commandInjection() throws Exception {
        String cmd = source(991);
        Runtime.getRuntime().exec("sh -c echo " + cmd);
    }

    // CWE-22 style: path traversal / arbitrary file read
    public void vuln_0992_pathTraversal() throws Exception {
        String fileName = source(992);
        File f = new File("/tmp/uploads/" + fileName);
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            sink(br.readLine());
        }
    }

    // CWE-79 style: reflected XSS-like output encoding issue
    public void vuln_0993_reflectedOutput() {
        String value = source(993);
        response.write("<html><body>" + value + "</body></html>");
    }

    // CWE-601 style: open redirect
    public void vuln_0994_openRedirect() {
        String next = source(994);
        response.sendRedirect(next);
    }

    // CWE-798 style: hardcoded credential
    public void vuln_0995_hardcodedSecret() {
        String password = "Password123!_DoNotUse_995";
        String apiKey = "AKIA_TEST_ONLY_0995_NOT_REAL";
        sink(password + apiKey);
    }

    // CWE-113 style: response header injection
    public void vuln_0996_headerInjection() {
        String headerValue = header(996);
        response.addHeader("X-Test-Header", headerValue);
    }

    // CWE-502 style: unsafe deserialization
    public Object vuln_0997_unsafeDeserialization(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // CWE-327/CWE-328 style: weak crypto/hash primitive
    public int vuln_0998_weakHash() {
        String input = source(998);
        return input.hashCode();
    }

    // CWE-200 style: sensitive information exposure in logs
    public void vuln_0999_sensitiveLog() {
        String token = source(999);
        System.out.println("user token=" + token);
    }

}
