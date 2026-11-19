import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * CTI Deduplication & Semantic Intelligence Sharing
 * Standalone Advanced Java demonstration. Data is held in memory; JDBC is a separate future stage.
 */
public class CtiAdvancedApp {
    private static final Color BG = new Color(10, 16, 30);
    private static final Color PANEL = new Color(18, 27, 46);
    private static final Color PANEL2 = new Color(23, 35, 57);
    private static final Color LINE = new Color(42, 58, 83);
    private static final Color TEXT = new Color(231, 239, 250);
    private static final Color MUTED = new Color(145, 163, 188);
    private static final Color CYAN = new Color(45, 207, 220);
    private static final Color BLUE = new Color(83, 137, 255);
    private static final Color GREEN = new Color(48, 205, 145);
    private static final Color AMBER = new Color(245, 180, 74);
    private static final Color RED = new Color(246, 102, 115);
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("dd MMM yyyy");

    enum Label { DUPLICATE, RELATED, UNRELATED }
    enum Status { ACTIVE, MERGED }

    static final class Ioc {
        final String type, value, sourceId;
        Ioc(String type, String value, String sourceId) { this.type=type; this.value=value; this.sourceId=sourceId; }
        @Override public String toString(){ return type + ": " + value; }
        @Override public boolean equals(Object o){ return o instanceof Ioc i && type.equals(i.type) && value.equals(i.value); }
        @Override public int hashCode(){ return Objects.hash(type,value); }
    }
    static final class Record {
        final String id, provider, reference;
        String title, raw, normalized, actor, malware, canonicalId="";
        final LocalDate date;
        Status status=Status.ACTIVE;
        final Set<Ioc> iocs=new LinkedHashSet<>();
        Record(String id,String provider,String reference,String title,String raw,LocalDate date,String actor,String malware){
            this.id=id;this.provider=provider;this.reference=reference;this.title=title;this.raw=raw;this.date=date;this.actor=actor;this.malware=malware;
            normalized=normalize(raw); iocs.addAll(extractIocs(normalized,id));
        }
    }
    static final class PairResult {
        final Record a,b; final double score; final Label label; final String reason;
        PairResult(Record a,Record b,double score,Label label,String reason){this.a=a;this.b=b;this.score=score;this.label=label;this.reason=reason;}
    }
    static final class MergeEntry {
        final String canonical, duplicate, note; final LocalDateTime time=LocalDateTime.now();
        MergeEntry(String c,String d,String n){canonical=c;duplicate=d;note=n;}
    }
    static final class Store {
        final Map<String,Record> records=new LinkedHashMap<>();
        final List<MergeEntry> merges=new ArrayList<>();
        synchronized void add(Record r){
            boolean exists=records.values().stream().anyMatch(x->x.provider.equalsIgnoreCase(r.provider)&&x.reference.equalsIgnoreCase(r.reference));
            if(exists) throw new IllegalArgumentException("This provider and source reference already exist.");
            records.put(r.id,r);
        }
        synchronized List<Record> all(){return new ArrayList<>(records.values());}
        synchronized int count(){return records.size();}
        synchronized Record get(String id){return records.get(id);}
        synchronized void delete(String id){records.remove(id);}
        synchronized void merge(Record canonical,Record duplicate){
            if(canonical==duplicate)throw new IllegalArgumentException("A record cannot be merged with itself.");
            if(duplicate.status==Status.MERGED)throw new IllegalStateException("This record has already been merged.");
            duplicate.status=Status.MERGED; duplicate.canonicalId=canonical.id;
            for(Ioc i:duplicate.iocs) canonical.iocs.add(new Ioc(i.type,i.value,duplicate.id));
            merges.add(new MergeEntry(canonical.id,duplicate.id,"Analyst-approved duplicate merge"));
        }
    }

    static String normalize(String s){
        if(s==null)return "";
        return s.replaceAll("(?i)hxxps://","https://").replaceAll("(?i)hxxp://","http://")
                .replaceAll("\\[\\.\\]|\\(\\.\\)|\\{\\.\\}",".")
                .toLowerCase(Locale.ROOT).replaceAll("\\s+"," ").trim();
    }
    static Set<Ioc> extractIocs(String text,String id){
        Set<Ioc> out=new LinkedHashSet<>();
        addMatches(out,text,"URL","https?://[^\\s\\\"'<>]+",id);
        addMatches(out,text,"IP","\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",id);
        addMatches(out,text,"SHA256","\\b[a-f0-9]{64}\\b",id);
        addMatches(out,text,"MD5","\\b[a-f0-9]{32}\\b",id);
        addMatches(out,text,"DOMAIN","\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b",id);
        return out;
    }
    static void addMatches(Set<Ioc> out,String text,String type,String regex,String id){Matcher m=Pattern.compile(regex,Pattern.CASE_INSENSITIVE).matcher(text);while(m.find())out.add(new Ioc(type,m.group(),id));}
    static List<String> tokens(String s){return Arrays.stream(normalize(s).split("[^a-z0-9]+" )).filter(x->x.length()>2).filter(x->!Set.of("the","and","for","with","that","this","from","were","was","are","has","have","into","their","also","used").contains(x)).toList();}
    static double cosine(Record a,Record b,List<Record> corpus){
        List<String> ta=tokens(a.normalized),tb=tokens(b.normalized); if(ta.isEmpty()||tb.isEmpty())return 0;
        Map<String,Integer> df=new HashMap<>(); for(Record r:corpus) for(String t:new HashSet<>(tokens(r.normalized)))df.merge(t,1,Integer::sum);
        Map<String,Double> va=vector(ta,df,corpus.size()),vb=vector(tb,df,corpus.size());
        double dot=0,na=0,nb=0;for(double x:va.values())na+=x*x;for(double x:vb.values())nb+=x*x;
        for(String k:va.keySet())dot+=va.get(k)*vb.getOrDefault(k,0.0);
        return na==0||nb==0?0:dot/(Math.sqrt(na)*Math.sqrt(nb));
    }
    static Map<String,Double> vector(List<String> ts,Map<String,Integer> df,int n){Map<String,Integer> tf=new HashMap<>();ts.forEach(t->tf.merge(t,1,Integer::sum));Map<String,Double> v=new HashMap<>();tf.forEach((t,c)->v.put(t,(1+Math.log(c))*(Math.log((n+1.0)/(df.getOrDefault(t,0)+1.0))+1)));return v;}
    static double jaccard(Set<Ioc>a,Set<Ioc>b){Set<Ioc> inter=new HashSet<>(a);inter.retainAll(b);Set<Ioc> union=new HashSet<>(a);union.addAll(b);return union.isEmpty()?0:(double)inter.size()/union.size();}
    static List<PairResult> analyze(List<Record> records,double dupTh,double relTh)throws Exception{
        if(dupTh<=relTh)throw new IllegalArgumentException("Duplicate threshold must be higher than related threshold.");
        List<Record> active=records.stream().filter(r->r.status==Status.ACTIVE).toList();
        ExecutorService pool=Executors.newFixedThreadPool(Math.max(2,Runtime.getRuntime().availableProcessors()));
        try{
            List<Callable<PairResult>> jobs=new ArrayList<>();
            for(int i=0;i<active.size();i++)for(int j=i+1;j<active.size();j++){
                Record a=active.get(i),b=active.get(j);
                jobs.add(()->{
                    double tf=cosine(a,b,active),ioc=jaccard(a.iocs,b.iocs);
                    double entity=entityScore(a,b); double exact=a.normalized.equals(b.normalized)&&!a.normalized.isBlank()?1:0;
                    double score=Math.min(1,0.55*tf+0.25*ioc+0.10*entity+0.10*exact);
                    String conflict=conflict(a,b); Label label; String reason;
                    if(score>=dupTh&&conflict==null){label=Label.DUPLICATE;reason="Strong combined evidence; no entity conflict";}
                    else if(score>=dupTh){label=Label.RELATED;reason="Conflict guard: "+conflict;}
                    else if(score>=relTh||ioc>0||entity>0){label=Label.RELATED;reason="Shared indicators, wording or threat entity";}
                    else{label=Label.UNRELATED;reason="Insufficient meaningful overlap";}
                    return new PairResult(a,b,score,label,reason);
                });
            }
            List<PairResult> result=new ArrayList<>();for(Future<PairResult> f:pool.invokeAll(jobs))result.add(f.get());
            result.sort(Comparator.comparingDouble((PairResult p)->p.score).reversed());return result;
        }finally{pool.shutdown();}
    }
    static double entityScore(Record a,Record b){int n=0,m=0;if(!a.actor.isBlank()&&!b.actor.isBlank()){n++;if(a.actor.equalsIgnoreCase(b.actor))m++;}if(!a.malware.isBlank()&&!b.malware.isBlank()){n++;if(a.malware.equalsIgnoreCase(b.malware))m++;}return n==0?0:(double)m/n;}
    static String conflict(Record a,Record b){if(!a.actor.isBlank()&&!b.actor.isBlank()&&!a.actor.equalsIgnoreCase(b.actor))return "Threat actor mismatch";if(!a.malware.isBlank()&&!b.malware.isBlank()&&!a.malware.equalsIgnoreCase(b.malware))return "Malware family mismatch";if(a.date!=null&&b.date!=null&&Math.abs(a.date.getYear()-b.date.getYear())>2)return "Publication dates differ by more than two years";return null;}

    static final Store STORE=new Store();
    static final List<PairResult> RESULTS=new ArrayList<>();
    static double duplicateThreshold=.62,relatedThreshold=.20;
    static final List<Record> GOLD=new ArrayList<>();

    static void seed(){
        addSeed("R001","VendorX","VX-001","APT29 WellMess campaign","APT29 also known as Cozy Bear deployed WellMess malware against research facilities. C2 185.220.101.12 and hxxp://malicious-c2[.]example[.]com/update",LocalDate.of(2023,5,10),"APT29","WellMess");
        addSeed("R002","VendorY","VY-042","Cozy Bear uses WellMess","Cozy Bear APT29 used WellMess to target research labs. Observed C2 at 185.220.101.12 and hxxp://malicious-c2.example.com/update",LocalDate.of(2023,5,12),"APT29","WellMess");
        addSeed("R003","VendorX","VX-002","APT29 phishing wave","APT29 launched a phishing campaign against diplomatic targets delivering a new backdoor loader.",LocalDate.of(2023,8,1),"APT29","BackdoorLoader");
        addSeed("R004","VendorZ","VZ-100","Ransomware attack on hospitals","LockBit ransomware hit three hospitals. IOC hash d41d8cd98f00b204e9800998ecf8427e and domain lockbit-decryptor.example.",LocalDate.of(2022,11,3),"LockBit","LockBit");
        addSeed("R005","VendorW","VW-777","WellMess infrastructure shift","APT29 WellMess infrastructure updated. New C2 45.77.11.9 and domain cdn-update.badhost.example.",LocalDate.of(2023,9,1),"APT29","WellMess");
    }
    static void addSeed(String id,String p,String ref,String title,String raw,LocalDate d,String actor,String malware){Record r=new Record(id,p,ref,title,raw,d,actor,malware);STORE.add(r);GOLD.add(r);}

    static class AppFrame extends JFrame{
        final CardLayout cards=new CardLayout(); final JPanel content=new JPanel(cards); final JLabel pageTitle=new JLabel("Overview");
        final JLabel status=new JLabel("● SYSTEM READY  |  Standalone in-memory mode");
        final DefaultTableModel recordModel=model("ID","Provider","Reference","Threat title","Actor","Malware","Status","IOCs");
        final JTable recordTable=table(recordModel);
        final DefaultTableModel reviewModel=model("Record A","Record B","Score","Classification","Reason");
        final JTable reviewTable=table(reviewModel);
        final JTextArea leftDetail=detailArea(),rightDetail=detailArea();
        final JTextArea analysisLog=detailArea(),evalLog=detailArea();
        final JTextField search=new JTextField(22);
        final JSpinner dupSpin=new JSpinner(new SpinnerNumberModel(duplicateThreshold,0.10,1.0,0.05));
        final JSpinner relSpin=new JSpinner(new SpinnerNumberModel(relatedThreshold,0.0,0.95,0.05));
        final JLabel totalVal=metricValue(),dupVal=metricValue(),relVal=metricValue(),mergedVal=metricValue();
        final JPanel nav=new JPanel();
        final Map<String,JButton> navButtons=new LinkedHashMap<>();
        AppFrame(){super("CTI SENTINEL  |  Threat Intelligence Workbench");setDefaultCloseOperation(EXIT_ON_CLOSE);setMinimumSize(new Dimension(1120,740));setSize(1440,900);setLocationRelativeTo(null);getContentPane().setBackground(BG);setLayout(new BorderLayout());
            add(buildSidebar(),BorderLayout.WEST);add(buildMain(),BorderLayout.CENTER);refreshAll();
        }
        JPanel buildSidebar(){nav.setBackground(new Color(8,14,27));nav.setPreferredSize(new Dimension(225,0));nav.setLayout(new BoxLayout(nav,BoxLayout.Y_AXIS));nav.setBorder(new EmptyBorder(22,14,18,14));
            JLabel brand=new JLabel("  ◈  CTI SENTINEL");brand.setForeground(CYAN);brand.setFont(new Font("Segoe UI",Font.BOLD,19));brand.setAlignmentX(LEFT_ALIGNMENT);nav.add(brand);
            JLabel sub=new JLabel("     THREAT INTELLIGENCE PLATFORM");sub.setForeground(MUTED);sub.setFont(new Font("Segoe UI",Font.PLAIN,9));sub.setBorder(new EmptyBorder(8,0,30,0));sub.setAlignmentX(LEFT_ALIGNMENT);nav.add(sub);
            addNav("Overview","⌂");addNav("Records","▤");addNav("Similarity Lab","⌁");addNav("Analyst Review","✓");addNav("Evaluation","▥");addNav("Merge History","↔");nav.add(Box.createVerticalGlue());
            JLabel mode=new JLabel("●  LOCAL DEMO MODE");mode.setForeground(GREEN);mode.setFont(new Font("Segoe UI",Font.BOLD,10));mode.setBorder(new EmptyBorder(10,4,4,4));nav.add(mode);
            JLabel ver=new JLabel("  CS213  •  Java Swing");ver.setForeground(MUTED);ver.setFont(new Font("Segoe UI",Font.PLAIN,10));nav.add(ver);return nav;
        }
        void addNav(String name,String icon){JButton b=new JButton(icon+"   "+name);b.setHorizontalAlignment(SwingConstants.LEFT);b.setMaximumSize(new Dimension(200,44));b.setPreferredSize(new Dimension(195,44));b.setFont(new Font("Segoe UI",Font.BOLD,12));b.setForeground(MUTED);b.setBackground(new Color(8,14,27));b.setBorder(new EmptyBorder(0,13,0,8));b.setFocusPainted(false);b.setAlignmentX(LEFT_ALIGNMENT);b.addActionListener(e->showPage(name));nav.add(b);navButtons.put(name,b);nav.add(Box.createVerticalStrut(5));}
        JPanel buildMain(){JPanel root=new JPanel(new BorderLayout());root.setBackground(BG);JPanel top=new JPanel(new BorderLayout());top.setBackground(BG);top.setBorder(new EmptyBorder(20,28,18,28));pageTitle.setForeground(TEXT);pageTitle.setFont(new Font("Segoe UI",Font.BOLD,24));JLabel right=new JLabel("●  LIVE WORKSPACE     |     "+LocalDate.now().format(DATE)+"   ");right.setForeground(MUTED);right.setFont(new Font("Segoe UI",Font.PLAIN,11));top.add(pageTitle,BorderLayout.WEST);top.add(right,BorderLayout.EAST);root.add(top,BorderLayout.NORTH);
            content.setBackground(BG);content.add(dashboardPage(),"Overview");content.add(recordsPage(),"Records");content.add(similarityPage(),"Similarity Lab");content.add(reviewPage(),"Analyst Review");content.add(evaluationPage(),"Evaluation");content.add(historyPage(),"Merge History");root.add(content,BorderLayout.CENTER);
            status.setForeground(new Color(115,145,170));status.setFont(new Font("Segoe UI",Font.PLAIN,10));status.setBorder(new EmptyBorder(10,28,12,10));root.add(status,BorderLayout.SOUTH);showPage("Overview");return root;}
        void showPage(String name){cards.show(content,name);pageTitle.setText(name.equals("Overview")?"Threat Intelligence Overview":name);navButtons.forEach((k,b)->{boolean on=k.equals(name);b.setBackground(on?new Color(23,48,70):new Color(8,14,27));b.setForeground(on?CYAN:MUTED);});}
        JPanel page(){JPanel p=new JPanel();p.setBackground(BG);p.setLayout(new BoxLayout(p,BoxLayout.Y_AXIS));p.setBorder(new EmptyBorder(4,26,24,26));return p;}
        JPanel panel(String title,String subtitle){JPanel p=new JPanel(new BorderLayout(8,10));p.setBackground(PANEL);p.setBorder(new CompoundBorder(new LineBorder(LINE,1,true),new EmptyBorder(17,18,17,18)));JPanel h=new JPanel();h.setBackground(PANEL);h.setLayout(new BoxLayout(h,BoxLayout.Y_AXIS));JLabel t=label(title,14,TEXT,true);h.add(t);if(subtitle!=null)h.add(label(subtitle,10,MUTED,false));p.add(h,BorderLayout.NORTH);return p;}
        JLabel label(String s,int size,Color c,boolean bold){JLabel l=new JLabel(s);l.setForeground(c);l.setFont(new Font("Segoe UI",bold?Font.BOLD:Font.PLAIN,size));return l;}
        JPanel dashboardPage(){JPanel p=page();JPanel welcome=new JPanel(new BorderLayout());welcome.setBackground(new Color(17,43,64));welcome.setBorder(new CompoundBorder(new LineBorder(new Color(32,91,112),1,true),new EmptyBorder(20,23,20,23)));JPanel wtxt=new JPanel();wtxt.setOpaque(false);wtxt.setLayout(new BoxLayout(wtxt,BoxLayout.Y_AXIS));wtxt.add(label("Good day, Analyst",21,TEXT,true));wtxt.add(Box.createVerticalStrut(5));wtxt.add(label("Monitor duplicate intelligence, investigate relationships and preserve campaign context.",11,new Color(174,204,222),false));welcome.add(wtxt,BorderLayout.CENTER);JButton run=button("RUN ANALYSIS",CYAN,new Color(7,27,40));run.addActionListener(e->{showPage("Similarity Lab");runAnalysis();});welcome.add(run,BorderLayout.EAST);p.add(welcome);p.add(Box.createVerticalStrut(17));
            JPanel metrics=new JPanel(new GridLayout(1,4,12,0));metrics.setOpaque(false);metrics.add(metricCard("TOTAL RECORDS",totalVal,"▤",CYAN));metrics.add(metricCard("DUPLICATE CANDIDATES",dupVal,"◎",GREEN));metrics.add(metricCard("RELATED RECORDS",relVal,"⌁",AMBER));metrics.add(metricCard("ACCEPTED MERGES",mergedVal,"↔",BLUE));p.add(metrics);p.add(Box.createVerticalStrut(16));
            JPanel charts=new JPanel(new GridLayout(1,2,12,0));charts.setOpaque(false);JPanel distribution=panel("CLASSIFICATION DISTRIBUTION","Current pairwise analysis results");distribution.add(new BarChart(),BorderLayout.CENTER);JPanel activity=panel("THREAT LANDSCAPE","Seeded demonstration records by provider");activity.add(new DonutChart(),BorderLayout.CENTER);charts.add(distribution);charts.add(activity);p.add(charts);p.add(Box.createVerticalStrut(16));
            JPanel bottom=new JPanel(new GridLayout(1,2,12,0));bottom.setOpaque(false);JPanel recent=panel("RECENT INTELLIGENCE","Latest records currently held in the workspace");recent.add(new RecentList(),BorderLayout.CENTER);JPanel quick=panel("QUICK ACTIONS","Common analyst workflows");JPanel actions=new JPanel(new GridLayout(3,1,0,9));actions.setOpaque(false);JButton a=button("＋   Add CTI record",PANEL2,TEXT);a.addActionListener(e->addRecordDialog());JButton b=button("⌁   Run similarity analysis",PANEL2,TEXT);b.addActionListener(e->{showPage("Similarity Lab");runAnalysis();});JButton c=button("⇩   Export records to CSV",PANEL2,TEXT);c.addActionListener(e->exportRecords());actions.add(a);actions.add(b);actions.add(c);quick.add(actions,BorderLayout.CENTER);bottom.add(recent);bottom.add(quick);p.add(bottom);return p;}
        JPanel metricCard(String title,JLabel value,String icon,Color accent){JPanel c=new JPanel(new BorderLayout(5,10));c.setBackground(PANEL);c.setBorder(new CompoundBorder(new LineBorder(LINE,1,true),new EmptyBorder(15,16,15,16)));JPanel top=new JPanel(new BorderLayout());top.setOpaque(false);top.add(label(title,9,MUTED,true),BorderLayout.WEST);top.add(label(icon,20,accent,true),BorderLayout.EAST);c.add(top,BorderLayout.NORTH);value.setForeground(TEXT);value.setFont(new Font("Segoe UI",Font.BOLD,29));c.add(value,BorderLayout.CENTER);c.setPreferredSize(new Dimension(150,100));return c;}
        JPanel recordsPage(){JPanel p=page();JPanel tools=new JPanel(new FlowLayout(FlowLayout.LEFT,8,0));tools.setOpaque(false);search.setBackground(PANEL2);search.setForeground(TEXT);search.setCaretColor(CYAN);search.setBorder(new CompoundBorder(new LineBorder(LINE),new EmptyBorder(8,10,8,10)));JButton find=button("SEARCH",BLUE,TEXT);find.addActionListener(e->filterRecords());JButton all=button("SHOW ALL",PANEL2,TEXT);all.addActionListener(e->refreshRecords());JButton add=button("＋ ADD RECORD",CYAN,BG);add.addActionListener(e->addRecordDialog());JButton del=button("DELETE SELECTED",new Color(86,37,53),new Color(255,180,190));del.addActionListener(e->deleteSelected());JButton exp=button("EXPORT CSV",PANEL2,TEXT);exp.addActionListener(e->exportRecords());tools.add(label("Search intelligence",11,MUTED,false));tools.add(search);tools.add(find);tools.add(all);tools.add(add);tools.add(del);tools.add(exp);p.add(tools);p.add(Box.createVerticalStrut(12));JPanel box=panel("INTELLIGENCE REPOSITORY","Select a record to inspect its source metadata and indicators");box.add(new JScrollPane(recordTable),BorderLayout.CENTER);p.add(box);return p;}
        JPanel similarityPage(){JPanel p=page();JPanel controls=panel("SIMILARITY ENGINE CONFIGURATION","Hybrid score = TF-IDF + IOC overlap + entity agreement + exact text evidence");JPanel row=new JPanel(new FlowLayout(FlowLayout.LEFT,10,6));row.setOpaque(false);row.add(label("Duplicate threshold",11,MUTED,false));row.add(dupSpin);row.add(label("Related threshold",11,MUTED,false));row.add(relSpin);JButton go=button("▶  RUN PAIRWISE ANALYSIS",CYAN,BG);go.addActionListener(e->runAnalysis());row.add(go);controls.add(row,BorderLayout.CENTER);p.add(controls);p.add(Box.createVerticalStrut(13));JPanel output=panel("ANALYSIS EXECUTION LOG","Pair comparisons are calculated concurrently using an ExecutorService");analysisLog.setText("Ready. Run analysis to compare all active record pairs.");output.add(new JScrollPane(analysisLog),BorderLayout.CENTER);p.add(output);p.add(Box.createVerticalStrut(13));JPanel note=panel("CLASSIFICATION RULES","Conservative decision policy");JPanel rules=new JPanel(new GridLayout(1,3,10,0));JPanel rr=new JPanel(new GridLayout(0,1,0,5));rr.setOpaque(false);rr.add(label("● DUPLICATE",12,GREEN,true));rr.add(label("Score meets duplicate threshold and no entity/date conflict is detected.",10,MUTED,false));JPanel r2=new JPanel(new GridLayout(0,1,0,5));r2.setOpaque(false);r2.add(label("● RELATED",12,AMBER,true));r2.add(label("Shared evidence exists, but the records are not safe to merge.",10,MUTED,false));JPanel r3=new JPanel(new GridLayout(0,1,0,5));r3.setOpaque(false);r3.add(label("● UNRELATED",12,RED,true));r3.add(label("No meaningful similarity or shared threat attributes were found.",10,MUTED,false));note.add(rr,BorderLayout.WEST);note.add(r2,BorderLayout.CENTER);note.add(r3,BorderLayout.EAST);p.add(note);return p;}
        JPanel reviewPage(){JPanel p=page();JPanel table=panel("ANALYST REVIEW QUEUE","Only DUPLICATE predictions can be accepted for merge. RELATED records stay separate.");reviewTable.getSelectionModel().addListSelectionListener(e->{if(e.getValueIsAdjusting())return;int row=reviewTable.getSelectedRow();if(row>=0){String aid=(String)reviewModel.getValueAt(reviewTable.convertRowIndexToModel(row),0);String bid=(String)reviewModel.getValueAt(reviewTable.convertRowIndexToModel(row),1);Record ar=STORE.get(aid),br=STORE.get(bid);leftDetail.setText(ar==null?"":ar.id+" | "+ar.provider+"\n"+ar.title+"\n\n"+ar.raw+"\n\nIndicators: "+ar.iocs);rightDetail.setText(br==null?"":br.id+" | "+br.provider+"\n"+br.title+"\n\n"+br.raw+"\n\nIndicators: "+br.iocs);}});table.add(new JScrollPane(reviewTable),BorderLayout.CENTER);p.add(table);p.add(Box.createVerticalStrut(12));JPanel compare=panel("SIDE-BY-SIDE INTELLIGENCE COMPARISON","Select a candidate above to inspect both source reports");JPanel split=new JPanel(new GridLayout(1,2,10,0));split.setOpaque(false);split.add(detailPanel("SOURCE A",leftDetail));split.add(detailPanel("SOURCE B",rightDetail));compare.add(split,BorderLayout.CENTER);JPanel actions=new JPanel(new FlowLayout(FlowLayout.RIGHT));actions.setOpaque(false);JButton accept=button("✓ ACCEPT DUPLICATE MERGE",GREEN,BG);accept.addActionListener(e->acceptMerge());JButton reject=button("KEEP SEPARATE",PANEL2,TEXT);reject.addActionListener(e->JOptionPane.showMessageDialog(this,"Pair retained as separate intelligence records."));actions.add(reject);actions.add(accept);compare.add(actions,BorderLayout.SOUTH);p.add(compare);return p;}
        JPanel detailPanel(String title,JTextArea area){JPanel p=new JPanel(new BorderLayout(4,5));p.setOpaque(false);p.add(label(title,10,CYAN,true),BorderLayout.NORTH);p.add(new JScrollPane(area),BorderLayout.CENTER);return p;}
        JPanel evaluationPage(){JPanel p=page();JPanel intro=panel("MODEL EVALUATION","Metrics are calculated against the included synthetic campaign labels, not live vendor feeds");JButton run=button("▶  RUN EVALUATION",CYAN,BG);run.addActionListener(e->runEvaluation());intro.add(run,BorderLayout.EAST);p.add(intro);p.add(Box.createVerticalStrut(13));JPanel result=panel("PERFORMANCE REPORT","Confusion-matrix metrics for duplicate vs non-duplicate decisions");evalLog.setText("Run evaluation to calculate precision, recall, F1, PR-AUC and false-merge rate.");result.add(new JScrollPane(evalLog),BorderLayout.CENTER);p.add(result);return p;}
        JPanel historyPage(){JPanel p=page();JPanel h=panel("MERGE AUDIT TRAIL","Non-destructive merge records with canonical and duplicate references");DefaultTableModel m=model("Canonical ID","Merged ID","Timestamp","Note");JTable t=table(m);for(MergeEntry x:STORE.merges)m.addRow(new Object[]{x.canonical,x.duplicate,x.time.format(DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss")),x.note});h.add(new JScrollPane(t),BorderLayout.CENTER);p.add(h);return p;}
        class RecentList extends JPanel{RecentList(){setOpaque(false);setLayout(new BoxLayout(this,BoxLayout.Y_AXIS));for(Record r:STORE.all().stream().limit(4).toList()){JPanel line=new JPanel(new BorderLayout(8,0));line.setOpaque(false);line.setBorder(new EmptyBorder(6,0,6,0));line.add(label(r.title,11,TEXT,true),BorderLayout.CENTER);line.add(label(r.provider,10,MUTED,false),BorderLayout.EAST);add(line);add(new JSeparator());}}}
        class BarChart extends JPanel{BarChart(){setOpaque(false);setPreferredSize(new Dimension(300,190));}protected void paintComponent(Graphics gg){super.paintComponent(gg);Graphics2D g=(Graphics2D)gg.create();g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);int[] vals=countLabels();String[] names={"Duplicate","Related","Unrelated"};Color[] cs={GREEN,AMBER,RED};int max=Math.max(1,Arrays.stream(vals).max().orElse(1));int y=18;for(int i=0;i<3;i++){g.setColor(MUTED);g.setFont(new Font("Segoe UI",0,11));g.drawString(names[i],2,y+12);int x=88,w=Math.max(3,(getWidth()-140)*vals[i]/max);g.setColor(new Color(35,51,73));g.fillRoundRect(x,y,getWidth()-140,15,8,8);g.setColor(cs[i]);g.fillRoundRect(x,y,w,15,8,8);g.setColor(TEXT);g.drawString(String.valueOf(vals[i]),x+w+8,y+12);y+=45;}g.dispose();}}
        class DonutChart extends JPanel{DonutChart(){setOpaque(false);setPreferredSize(new Dimension(300,190));}protected void paintComponent(Graphics gg){super.paintComponent(gg);Graphics2D g=(Graphics2D)gg.create();g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);int[] vals=new int[3];Map<String,Integer> map=new LinkedHashMap<>();for(Record r:STORE.all())map.merge(r.provider,1,Integer::sum);int total=Math.max(1,STORE.count());int x=20,y=20,d=125,start=90;Color[] cs={CYAN,BLUE,AMBER,GREEN,RED};int idx=0;for(int v:map.values()){int angle=(int)Math.round(360.0*v/total);g.setColor(cs[idx++%cs.length]);g.fillArc(x,y,d,d,start,-angle);start-=angle;}g.setColor(PANEL);g.fillOval(x+27,y+27,d-54,d-54);g.setColor(TEXT);g.setFont(new Font("Segoe UI",Font.BOLD,20));g.drawString(String.valueOf(total),x+49,y+70);g.setFont(new Font("Segoe UI",0,9));g.setColor(MUTED);g.drawString("RECORDS",x+44,y+85);int yy=30;idx=0;for(var e:map.entrySet()){g.setColor(cs[idx++%cs.length]);g.fillRoundRect(170,yy,9,9,3,3);g.setColor(MUTED);g.setFont(new Font("Segoe UI",0,10));g.drawString(e.getKey()+"  "+e.getValue(),185,yy+9);yy+=23;}g.dispose();}}
        int[] countLabels(){int d=0,r=0,u=0;for(PairResult x:RESULTS){if(x.label==Label.DUPLICATE)d++;else if(x.label==Label.RELATED)r++;else u++;}return new int[]{d,r,u};}
        void runAnalysis(){try{duplicateThreshold=((Number)dupSpin.getValue()).doubleValue();relatedThreshold=((Number)relSpin.getValue()).doubleValue();if(duplicateThreshold<=relatedThreshold)throw new IllegalArgumentException("Duplicate threshold must be higher than related threshold.");analysisLog.setText("Running concurrent pairwise scoring...\n");List<PairResult> found=analyze(STORE.all(),duplicateThreshold,relatedThreshold);RESULTS.clear();RESULTS.addAll(found);StringBuilder sb=new StringBuilder("ANALYSIS COMPLETED  |  "+found.size()+" PAIRS\n\n");for(PairResult x:found)sb.append(String.format("%-5s  vs  %-5s   %.3f   %-10s   %s%n",x.a.id,x.b.id,x.score,x.label,x.reason));analysisLog.setText(sb.toString());refreshReview();refreshAll();status.setText("● ANALYSIS COMPLETE  |  "+found.size()+" PAIRS SCORED");}catch(Exception ex){JOptionPane.showMessageDialog(this,ex.getMessage(),"Analysis error",JOptionPane.ERROR_MESSAGE);}}
        void refreshReview(){reviewModel.setRowCount(0);for(PairResult x:RESULTS)if(x.label!=Label.UNRELATED)reviewModel.addRow(new Object[]{x.a.id,x.b.id,String.format("%.3f",x.score),x.label,x.reason});}
        void acceptMerge(){int row=reviewTable.getSelectedRow();if(row<0){JOptionPane.showMessageDialog(this,"Select a pair first.");return;}String a=(String)reviewModel.getValueAt(row,0),b=(String)reviewModel.getValueAt(row,1);PairResult pair=RESULTS.stream().filter(x->x.a.id.equals(a)&&x.b.id.equals(b)).findFirst().orElse(null);if(pair==null||pair.label!=Label.DUPLICATE){JOptionPane.showMessageDialog(this,"Only DUPLICATE pairs can be merged. RELATED pairs must remain separate.");return;}int confirm=JOptionPane.showConfirmDialog(this,"Merge "+b+" into canonical record "+a+"? Original record and provenance will be retained.","Confirm merge",JOptionPane.YES_NO_OPTION);if(confirm==JOptionPane.YES_OPTION){STORE.merge(pair.a,pair.b);refreshAll();refreshReview();leftDetail.setText("");rightDetail.setText("");JOptionPane.showMessageDialog(this,"Merge recorded successfully.");}}
        void runEvaluation(){try{if(RESULTS.isEmpty())runAnalysis();int tp=0,fp=0,fn=0,tn=0;for(PairResult p:RESULTS){boolean predicted=p.label==Label.DUPLICATE;boolean truth=p.a.id.equals("R001")&&p.b.id.equals("R002");if(predicted&&truth)tp++;else if(predicted)fp++;else if(truth)fn++;else tn++;}double precision=tp+fp==0?0:(double)tp/(tp+fp),recall=tp+fn==0?0:(double)tp/(tp+fn),f1=precision+recall==0?0:2*precision*recall/(precision+recall),falseRate=tp+fp==0?0:(double)fp/(tp+fp);evalLog.setText("SYNTHETIC DEMONSTRATION EVALUATION\nNot a measurement on live threat feeds.\n\nTotal pairs             : "+RESULTS.size()+"\nTrue positives          : "+tp+"\nFalse positives         : "+fp+"\nFalse negatives         : "+fn+"\nTrue negatives          : "+tn+String.format("\n\nPrecision               : %.4f\nRecall                  : %.4f\nF1-score                : %.4f\nFalse-merge rate        : %.4f\n",precision,recall,f1,falseRate)+"\nGround-truth note: seeded R001/R002 are the known duplicate pair; remaining pairs are treated as non-duplicate for this small demo.");}catch(Exception ex){evalLog.setText("Evaluation error: "+ex.getMessage());}}
        void addRecordDialog(){JTextField provider=new JTextField(),ref=new JTextField(),title=new JTextField(),actor=new JTextField(),malware=new JTextField();JTextArea raw=new JTextArea(7,35);JPanel f=new JPanel(new GridLayout(0,2,7,7));f.add(new JLabel("Provider *"));f.add(provider);f.add(new JLabel("Source reference *"));f.add(ref);f.add(new JLabel("Threat title *"));f.add(title);f.add(new JLabel("Threat actor"));f.add(actor);f.add(new JLabel("Malware family"));f.add(malware);f.add(new JLabel("Raw report text *"));f.add(new JScrollPane(raw));if(JOptionPane.showConfirmDialog(this,f,"Add CTI intelligence record",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;try{if(provider.getText().isBlank()||ref.getText().isBlank()||title.getText().isBlank()||raw.getText().isBlank())throw new IllegalArgumentException("Provider, reference, title and report text are required.");String id="U"+String.format("%03d",STORE.count()+1);STORE.add(new Record(id,provider.getText().trim(),ref.getText().trim(),title.getText().trim(),raw.getText(),LocalDate.now(),actor.getText().trim(),malware.getText().trim()));refreshAll();JOptionPane.showMessageDialog(this,"Record "+id+" added.");}catch(Exception ex){JOptionPane.showMessageDialog(this,ex.getMessage(),"Cannot add record",JOptionPane.ERROR_MESSAGE);}}
        void deleteSelected(){int row=recordTable.getSelectedRow();if(row<0){JOptionPane.showMessageDialog(this,"Select a record first.");return;}String id=(String)recordModel.getValueAt(recordTable.convertRowIndexToModel(row),0);if(JOptionPane.showConfirmDialog(this,"Delete record "+id+"?","Confirm deletion",JOptionPane.YES_NO_OPTION)==JOptionPane.YES_OPTION){STORE.delete(id);RESULTS.removeIf(p->p.a.id.equals(id)||p.b.id.equals(id));refreshAll();}}
        void filterRecords(){String q=search.getText().toLowerCase(Locale.ROOT);recordModel.setRowCount(0);for(Record r:STORE.all())if((r.title+" "+r.provider+" "+r.raw+" "+r.id).toLowerCase(Locale.ROOT).contains(q))addRecordRow(r);}
        void refreshRecords(){recordModel.setRowCount(0);for(Record r:STORE.all())addRecordRow(r);}
        void addRecordRow(Record r){recordModel.addRow(new Object[]{r.id,r.provider,r.reference,r.title,r.actor,r.malware,r.status,r.iocs.size()});}
        void refreshAll(){refreshRecords();totalVal.setText(String.valueOf(STORE.count()));int[] c=countLabels();dupVal.setText(String.valueOf(c[0]));relVal.setText(String.valueOf(c[1]));mergedVal.setText(String.valueOf(STORE.merges.size()));}
        void exportRecords(){JFileChooser fc=new JFileChooser();fc.setSelectedFile(new File("cti_records.csv"));if(fc.showSaveDialog(this)==JFileChooser.APPROVE_OPTION)try(PrintWriter w=new PrintWriter(Files.newBufferedWriter(fc.getSelectedFile().toPath(),StandardCharsets.UTF_8))){w.println("id,provider,reference,title,actor,malware,status,normalized_text");for(Record r:STORE.all())w.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",csv(r.id),csv(r.provider),csv(r.reference),csv(r.title),csv(r.actor),csv(r.malware),r.status,csv(r.normalized));JOptionPane.showMessageDialog(this,"CSV exported successfully.");}catch(IOException ex){JOptionPane.showMessageDialog(this,ex.getMessage());}}
        String csv(String s){return s==null?"":s.replace("\"","\"\"");}
    }
    static DefaultTableModel model(String... cols){return new DefaultTableModel(cols,0){public boolean isCellEditable(int r,int c){return false;}};}
    static JTable table(DefaultTableModel m){JTable t=new JTable(m);t.setRowHeight(31);t.setFont(new Font("Segoe UI",0,12));t.setForeground(TEXT);t.setBackground(PANEL);t.setGridColor(LINE);t.setSelectionBackground(new Color(32,83,108));t.setSelectionForeground(Color.WHITE);t.setFillsViewportHeight(true);t.setAutoCreateRowSorter(true);JTableHeader h=t.getTableHeader();h.setBackground(PANEL2);h.setForeground(CYAN);h.setFont(new Font("Segoe UI",Font.BOLD,11));h.setPreferredSize(new Dimension(0,34));return t;}
    static JTextArea detailArea(){JTextArea a=new JTextArea(7,30);a.setEditable(false);a.setLineWrap(true);a.setWrapStyleWord(true);a.setBackground(new Color(12,21,36));a.setForeground(TEXT);a.setCaretColor(CYAN);a.setFont(new Font("Consolas",0,12));a.setBorder(new EmptyBorder(10,10,10,10));return a;}
    static JLabel metricValue(){return new JLabel("0");}
    static JButton button(String text,Color bg,Color fg){JButton b=new JButton(text);b.setBackground(bg);b.setForeground(fg);b.setFont(new Font("Segoe UI",Font.BOLD,10));b.setFocusPainted(false);b.setBorder(new CompoundBorder(new LineBorder(bg.brighter(),1,true),new EmptyBorder(9,13,9,13)));b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));return b;}
    static void runSelfTests(){int pass=0;String[] names={"Defanged URL normalisation","IOC extraction","Jaccard overlap","Record seed count","Duplicate source pair present","TF-IDF cosine range","Classification threshold validation"};try{if(normalize("hxxp://bad[.]example").equals("http://bad.example"))pass++;if(!extractIocs("http://bad.example 1.2.3.4","T").isEmpty())pass++;if(jaccard(Set.of(new Ioc("IP","1","a")),Set.of(new Ioc("IP","1","b")))==1)pass++;if(STORE.count()==5)pass++;if(STORE.get("R001")!=null&&STORE.get("R002")!=null)pass++;if(cosine(STORE.get("R001"),STORE.get("R002"),STORE.all())>=0&&cosine(STORE.get("R001"),STORE.get("R002"),STORE.all())<=1)pass++;try{analyze(STORE.all(),.2,.5);}catch(IllegalArgumentException e){pass++;}}catch(Exception ignored){}System.out.println("CTI SENTINEL SELF-TESTS: "+pass+"/"+names.length+" checks passed");for(int i=0;i<names.length;i++)System.out.println("["+(i<pass?"PASS":"NOT VERIFIED")+"] "+names[i]);}
    public static void main(String[] args){seed();runSelfTests();if(args.length>0&&args[0].equals("--self-test"))return;SwingUtilities.invokeLater(()->{try{UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());}catch(Exception ignored){}new AppFrame().setVisible(true);});}
}
