package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import java.io.*;
import java.util.*;
import java.util.List;
import java.util.Random;
import okhttp3.Response;
import okhttp3.Headers;
import org.apache.commons.lang3.RandomStringUtils;

/**
 * 0:log.xn--9tr.com
 * 1:ceye.io
 * 2:dnslog.cn
 * 3:privatedns
 */
abstract class dnslogFactory {
    public PrintWriter stdout;

    abstract public String getDnslogUrl();

    abstract public void initDnslog(PrintWriter stdout);

    /**
     * print current dnslog info
     */
    abstract public void printDnslog();

    /**
     * @return a Boolean if dnslog is working normally
     */
    abstract public Boolean checkDnslog();

    /**
     * pop a JOptionPane to tell if dnslog is working normally
     */
    abstract public String testDnslog();

    abstract public List<String> askDnslogRecordOnce();
}

class logxnFactory extends dnslogFactory {

    private String logxnDnslog;
    private String logxnDnslogToken;

    @Override
    public void initDnslog(PrintWriter stdout) {
        this.stdout = stdout;
        try {
            String indexUrl = "https://log.xn--9tr.com/new_gen";
            String respbody = BurpExtender.myRequest(indexUrl).body().string();
            JSONObject jsonObject = JSON.parseObject(String.valueOf(respbody));
            this.logxnDnslog = jsonObject.getString("domain");
            // this stupid website will add a '.' to the end of domain
            this.logxnDnslog = logxnDnslog.substring(0, logxnDnslog.length() - 1);
            this.logxnDnslogToken = jsonObject.getString("token");
        } catch (Exception e) {
            this.stdout.println("[E] using log.xn--9tr.com now but initialization failed!");
        }
    }

    @Override
    public String getDnslogUrl() {
        return this.logxnDnslog;
    }

    @Override
    public void printDnslog() {
        this.stdout.println("[+]using log.xn--9tr.com now!");
        this.stdout.println("[+]dns address : " + this.logxnDnslog);
        this.stdout.println("[+]dns token : " + this.logxnDnslogToken);
        this.stdout.println(
                "[+]You also can request to    https://log.xn--9tr.com/" + this.logxnDnslogToken + "    to see dnslog");
    }

    @Override
    public Boolean checkDnslog() {
        try {
            String indexUrl = "https://log.xn--9tr.com/" + this.logxnDnslogToken;
            Response response = BurpExtender.myRequest(indexUrl);
            if (response.body().string() != null && response.code() == 200)
                return true;
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    @Override
    public String testDnslog() {
        return checkDnslog() ? "Logxn is working normally." : "Logxn is not working!";
    }

    @Override
    public List<String> askDnslogRecordOnce() {

        List<String> random_str_list = new ArrayList<String>();
        try {
            Response response = BurpExtender.myRequest("https://log.xn--9tr.com/" + this.logxnDnslogToken);
            JSONObject jsonObject = JSON.parseObject(response.body().string());
            // check the subdomain
            for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
                String subdomain = JSON.parseObject(entry.getValue().toString()).getString("subdomain");
                if (subdomain.contains(this.logxnDnslog) && subdomain.length() > this.logxnDnslog.length() + 1) {
                    random_str_list.add(subdomain.split(this.logxnDnslog)[0]);
                }
            }
        } catch (Exception e) {
        }
        return random_str_list;
    }
}

class ceyeFactory extends dnslogFactory {

    private String ceyednslog;// ceye.io dnslog url(xxxxxx.ceye.io)
    private String ceyetoken;// ceye.io token

    public ceyeFactory(String a, String b) {
        this.ceyednslog = a;
        this.ceyetoken = b;
    }

    @Override
    public void initDnslog(PrintWriter stdout) {
        this.stdout = stdout;
    }

    @Override
    public String getDnslogUrl() {
        return this.ceyednslog;
    }

    @Override
    public void printDnslog() {
        this.stdout.println("[+]using ceye.io now!");
        this.stdout.println("[+]dns address : " + this.ceyednslog);
        this.stdout.println("[+]dns token : " + this.ceyetoken);
        this.stdout.println("[+]You also can request to    http://api.ceye.io/v1/records?token=" + this.ceyetoken
                + "&type=dns&filter=    to see dnslog");
    }

    @Override
    public Boolean checkDnslog() {
        if (this.ceyednslog == null || this.ceyetoken == null)
            return false;
        try {
            String indexUrl = " http://api.ceye.io/v1/records?token=" + this.ceyetoken + "&type=dns&filter=";
            String respbody = BurpExtender.myRequest(indexUrl).body().string();
            JSONObject jsonObject = JSON.parseObject(respbody);
            if (jsonObject.getJSONObject("meta").getIntValue("code") == 200)
                return true;
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    @Override
    public String testDnslog() {
        return checkDnslog() ? "Ceye.io is working normally." : "Ceye.io is not working!";
    }

    @Override
    public List<String> askDnslogRecordOnce() {
        List<String> random_str_list = new ArrayList<String>();
        try {
            Response response = BurpExtender
                    .myRequest("http://api.ceye.io/v1/records?token=" + this.ceyetoken + "&type=dns&filter=");
            JSONArray jsonarray = JSON.parseObject(response.body().string()).getJSONArray("data");
            for (int i = 0; i < jsonarray.size(); i++) {
                JSONObject jsonObject = jsonarray.getJSONObject(i);
                String subdomain = jsonObject.getString("name");
                if (subdomain.contains(this.ceyednslog) && subdomain.length() > this.ceyednslog.length()) {
                    random_str_list.add(subdomain.split(this.ceyednslog)[0]);
                }
            }
        } catch (Exception e) {
        }
        return random_str_list;
    }
}

class dnslogcnFactory extends dnslogFactory {

    private String dnslogcn;// dnslog.cn dnslog url(xxxxxx.dnslog.cn)
    private String dnslogcnSession;

    @Override
    public void initDnslog(PrintWriter stdout) {
        this.stdout = stdout;
        try {
            Random rand = new Random();
            String indexUrl = "http://dnslog.cn/getdomain.php?t=" + String.valueOf(rand.nextDouble());
            Response response = BurpExtender.myRequest(indexUrl);
            String respbody = response.body().string();
            ;
            Headers headers = response.headers();
            this.dnslogcn = respbody;
            List<String> values = headers.values("Set-Cookie");
            if (values != null && values.size() > 0) {
                StringBuilder sb = new StringBuilder();
                for (String s : values) {
                    sb.append(s);
                }
                this.dnslogcnSession = sb.toString();
            }
        } catch (Exception e) {
            this.stdout.println("[E] using dnslog.cn now but initialization failed!");
        }
    }

    @Override
    public String getDnslogUrl() {
        return this.dnslogcn;
    }

    @Override
    public void printDnslog() {
        this.stdout.println("[+]using dnslog.cn now!");
        this.stdout.println("[+]dns address : " + this.dnslogcn);
        this.stdout.println("[+]dns session : " + this.dnslogcnSession);
        this.stdout.println("[+]You also can request to    http://dnslog.cn/getrecords.php?t=[random] with session:"
                + this.dnslogcnSession + "    to see dnslog");
    }

    @Override
    public Boolean checkDnslog() {
        try {
            Random rand = new Random();
            String indexUrl = "http://dnslog.cn/getrecords.php?t=" + String.valueOf(rand.nextDouble());
            Response response = BurpExtender.myRequest(indexUrl);
            if (response.body().string() != null && response.code() == 200)
                return true;
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    @Override
    public String testDnslog() {
        return checkDnslog() ? "Dnslog.cn is working normally." : "Dnslog.cn is not working!";
    }

    @Override
    public List<String> askDnslogRecordOnce() {
        List<String> random_str_list = new ArrayList<String>();
        try {
            Random rand = new Random();
            Response response = BurpExtender
                    .myRequest("http://dnslog.cn/getrecords.php?t=" + String.valueOf(rand.nextDouble()));
            // how to parse things like [[string,string],[string,string]]?
            // this.stdout.println(response.body().toString());
            String[] subdomain = response.body().toString().split("\"");
            for (String _subdomain : subdomain) {
                if (_subdomain.contains(this.dnslogcn) && _subdomain.length() > this.dnslogcn.length()) {
                    random_str_list.add(_subdomain.split(this.dnslogcn)[0]);
                }
            }
        } catch (Exception e) {
        }
        return random_str_list;
    }
}

class privateFactory extends dnslogFactory {

    private String privatedns;

    public privateFactory(String a) {
        this.privatedns = a;
    }

    @Override
    public void initDnslog(PrintWriter stdout) {
        this.stdout = stdout;
    }

    @Override
    public String getDnslogUrl() {
        return this.privatedns;
    }

    @Override
    public void printDnslog() {
        this.stdout.println("[+]using private dnslog now!");
        this.stdout.println("[+]dns address : " + this.privatedns);
        this.stdout.println("[+]Auto check is disabled");
        this.stdout.println("[+]You need to check the dns record manully");
    }

    @Override
    public Boolean checkDnslog() {
        return false;
    }

    @Override
    public String testDnslog() {
        return "Auto check is disabled, You need to check the dns record manully!";
    }

    @Override
    public List<String> askDnslogRecordOnce() {
        List<String> random_str_list = new ArrayList<String>();
        return random_str_list;
    }
}
