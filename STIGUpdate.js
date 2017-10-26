

// A new blank checklist generated from the current STIG
var newChecklist = 'C:\\Users\\NToomey\\Documents\\Projects\\Navy CAMS\\As-Built\\Checklists\\MS SQL\\MSSQL2014Database.ckl';

// An existing Checklist that has settings to be imported into the new checklist
var oldChecklist = 'C:\\Users\\NToomey\\Documents\\Projects\\Navy CAMS\\As-Built\\Checklists\\MS SQL\\SQL 2014 Database.ckl';

var parser = require('xml2js');
var js2xmlparser = require("js2xmlparser");
var fs = require('fs');

var importData = "";

// open old format checklist
fs.readFile(oldChecklist, "utf8", function(err, data) {
    if (err) console.log(err);
    
    parser.parseString(data, function(err, importD) {
        if (err) console.log(err);
        importData = importD;
    });
});

// open new format checklist
fs.readFile(newChecklist, "utf8", function(err, data) {
    if (err) console.log(err, err.stack);
    parser.parseString(data, function (err, exportData) {
        if (err) console.log(err, err.stack);
        
        //console.log(exportData.CHECKLIST.ASSET);
        // copy over asset details
        exportData.CHECKLIST.ASSET.forEach(function(i){
                i.HOST_NAME = importData.CHECKLIST.ASSET[0].HOST_NAME;
                i.HOST_IP = importData.CHECKLIST.ASSET[0].HOST_IP;
                i.HOST_MAC = importData.CHECKLIST.ASSET[0].HOST_MAC;
                i.HOST_GUID = importData.CHECKLIST.ASSET[0].HOST_GUID;
                i.HOST_FQDN = importData.CHECKLIST.ASSET[0].HOST_FQDN;
                i.TECH_AREA = importData.CHECKLIST.ASSET[0].TECH_AREA;
                i.TARGET_KEY = importData.CHECKLIST.ASSET[0].TARGET_KEY;
        });
             
        //console.log(importData.CHECKLIST.STIGS[0].iSTIG[0].VULN);
        var vuln = exportData.CHECKLIST.STIGS[0].iSTIG[0].VULN;
        // copy over vuln details
        vuln.forEach(function(b) {
                //console.log(b);
                //console.log(b.STIG_DATA);
                b.STIG_DATA.forEach(function(v){
                    //console.log(b.STATUS);
                    if (v.VULN_ATTRIBUTE == "Vuln_Num") {
                        findVuln(v.ATTRIBUTE_DATA[0], importData, function(data) {                               
                                if(data) {
                                    b.STATUS = data.STATUS;
                                    b.FINDING_DETAILS = data.FINDING_DETAILS;
                                    b.COMMENTS = data.COMMENTS;
                                }
                        });
                        
                    }
                });
               
        });
        
        // save new checklist
        fs.writeFile(oldChecklist+"export.ckl", js2xmlparser.parse("CHECKLIST",exportData), function (err) {
           if (err) console.log(err, err.stack); 
        });
        
    });
});

function findVuln(vulnNum, data, callback) {
    console.log("Searching for: " +vulnNum);
    
    data.CHECKLIST.STIGS[0].iSTIG[0].VULN.forEach(function(a) {
        a.STIG_DATA.forEach(function(n){
           if (n.VULN_ATTRIBUTE == "Vuln_Num"  && n.ATTRIBUTE_DATA[0] == vulnNum) {
               console.log("Found Vuln: "+ vulnNum)
               //console.log(b);
               return callback(a);
           } 
        });
    });
    //return 0
}
