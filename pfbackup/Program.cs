using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace pfbackup
{
    class PFSenseObject
    {
        public string RemoteHost = "";
        public uint RemotePort = 0;
        public Boolean UseSSL = false;
        public string Username = "";
        public string Password = "";
        public PFVersion pfVersion = PFVersion.V20X_V225;
        public uint BackupCopies = 5;
        public enum PFVersion
        {
            V20X_V225,
            V226_V232P1,
            V233_LATER
        }
    }
    class Program
    {
   
        public static void Main(string[] args)
        {
            Console.WriteLine("pfBackup v000.1a by Justin Oberdorf");
            Console.WriteLine("-----------------------------------");
            if (args.Length == 1)
            {
                string szEncryptedPassword = args[0].PfEncrypt("oxygen");
                Console.WriteLine("Original Password: {0}", szEncryptedPassword.PfDecrypt("oxygen"));
                Console.WriteLine("Encrypted Password: {0}",szEncryptedPassword);
                return;
            }
            MainAsync(args).Wait();
        }
        static async Task MainAsync(string[] args)
        {
            PFSenseObject[] fireWalls = null;
            if (File.Exists("pfbackup.config"))
            {
                try {
                    fireWalls = JsonConvert.DeserializeObject<PFSenseObject[]>(File.ReadAllText("pfbackup.config"));
                    Console.WriteLine("[INFO] Loaded {0} firewall(s)", fireWalls.Length);
                }   
                catch
                {
                    Console.WriteLine("[ERROR] Unable to load pfbackup.config - Exiting.");
                    return;
                }
                Console.WriteLine("[INFO] Starting Configuration Backups");
                //TODO: Add CSRF Support for Later Versions, need install latest in VM
                foreach(PFSenseObject fireWall in fireWalls)
                {
                    Console.WriteLine("[INFO] Processing\r\n[INFO] Host: {0}", fireWall.RemoteHost);
                    //Create Uri based on remote host, port and SSL or nahhhhh
                    Uri firewallUri = (fireWall.UseSSL == true) ? new Uri("https://" + fireWall.RemoteHost + ":" + fireWall.RemotePort + "/diag_backup.php") : new Uri("http://" + fireWall.RemoteHost + ":" + fireWall.RemotePort + "/diag_backup.php");
                    //Create handler and client
                    using (HttpClientHandler firewallClientHandler = new HttpClientHandler())
                    {
                        //Coooooookkkiiiiieee monster   
                        firewallClientHandler.CookieContainer = new CookieContainer();
                        firewallClientHandler.UseCookies = true;
                        firewallClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; };
                        using (HttpClient firewallClient = new HttpClient(firewallClientHandler))
                        {
                            HttpResponseMessage firewallResponse = null;
                            string szFirewallResponse = "";
                            string szCsrfMagic = "";
                            FormUrlEncodedContent firewallRequestContent = null;
                            firewallClient.DefaultRequestHeaders.Add("User-Agent","pfBackup Automated Config Backup");

                            //CSRF Step 1
                            try
                            {   
                                firewallResponse = await firewallClient.GetAsync(firewallUri);
                            }
                            catch (Exception Step1)
                            {
                                Console.WriteLine("[ERROR] Step 1 Exception Thrown");
                                continue;
                            }
                            if (firewallResponse.StatusCode != HttpStatusCode.OK)
                            {
                                Console.WriteLine("[ERROR] Step 1 Invalid Status Code");
                                continue;
                            }
                            szFirewallResponse = await firewallResponse.Content.ReadAsStringAsync();
                            szCsrfMagic = GetCsrfMagic(szFirewallResponse);
                            firewallResponse.Dispose();
                            firewallResponse = null;
                            szFirewallResponse = "";

                            //Login Step2
                            try
                            {
                                Dictionary<string, string> dLogin = new Dictionary<string, string>();
                                dLogin.Add("login", "Login");
                                dLogin.Add("usernamefld", fireWall.Username);
                                dLogin.Add("passwordfld", fireWall.Password.PfDecrypt("oxygen"));
                                if (!String.IsNullOrWhiteSpace(szCsrfMagic)) { dLogin.Add("__csrf_magic", szCsrfMagic);  }
                                szCsrfMagic = "";
                                firewallRequestContent = new FormUrlEncodedContent(dLogin);
                                firewallResponse = await firewallClient.PostAsync(firewallUri, firewallRequestContent);
                                
                            }   
                            catch (Exception Step2)
                            {

                                Console.WriteLine("[ERROR] Step 2 Exception Thrown");
                                continue;
                            }
                            if (firewallResponse.StatusCode != HttpStatusCode.OK)
                            {
                                Console.WriteLine("[ERROR] Step 2 Invalid Status Code");
                                continue;
                            }
                            szFirewallResponse = await firewallResponse.Content.ReadAsStringAsync();
                            if (szFirewallResponse.Contains("Username or Password incorrect"))
                            {
                                Console.WriteLine("[ERROR] Step 2 Invalid Credentials");
                                continue;
                            }
                            szCsrfMagic = GetCsrfMagic(szFirewallResponse);
                            firewallResponse.Dispose();
                            firewallResponse = null;
                            szFirewallResponse = "";

                            //Download Config Step 3
                            try
                            {
                                Dictionary<string, string> dDownload = new Dictionary<string, string>();
                                dDownload.Add("backuparea", "");
                                switch (fireWall.pfVersion)
                                {
                                    case PFSenseObject.PFVersion.V20X_V225:
                                    case PFSenseObject.PFVersion.V226_V232P1:
                                        dDownload.Add("donotbackuprrd", "on");
                                        dDownload.Add("Submit", "Download configuration");
                                        break;
                                    case PFSenseObject.PFVersion.V233_LATER:
                                        dDownload.Add("donotbackuprrd", "yes");
                                        dDownload.Add("download", "Download configuration as XML");
                                        break;
                                }
                                
                                dDownload.Add("encrypt_password", "");
                                dDownload.Add("encrypt_passconf", "");
                                
                                if (!String.IsNullOrWhiteSpace(szCsrfMagic)) { dDownload.Add("__csrf_magic", szCsrfMagic); }
                                szCsrfMagic = "";
                                firewallRequestContent = new FormUrlEncodedContent(dDownload);
                                firewallResponse = await firewallClient.PostAsync(firewallUri, firewallRequestContent);
                            }
                            catch (Exception Step3)
                            {

                                Console.WriteLine("[ERROR] Step 3 Exception Thrown");
                                continue;
                            }
                            if (firewallResponse.StatusCode != HttpStatusCode.OK)
                            {
                                Console.WriteLine("[ERROR] Step 3 Invalid Status Code");
                                continue;
                            }
                            szFirewallResponse = await firewallResponse.Content.ReadAsStringAsync();
                            if (!szFirewallResponse.StartsWith("<?xml version=\"1.0\"?>\n<pfsense>"))
                            {
                                Console.WriteLine("[ERROR] Step 3 Invalid Configuration Found");
                                continue;
                            }
                            //Save the files Step 4
                            if (!Directory.Exists(".\\backup")) { Directory.CreateDirectory(".\\backup"); }
                            string szFirewallDirectory = ".\\backup\\" + GetSafeFileName(fireWall.RemoteHost);
                            if (!Directory.Exists(szFirewallDirectory)) { Directory.CreateDirectory(szFirewallDirectory);  }
                            string szFirewallConfigFilename = GetSafeFileName(fireWall.RemoteHost + "_" + firewallResponse.Content.Headers.ContentDisposition.FileName);
                            try
                            {
                                if (File.Exists(szFirewallDirectory + "\\" + szFirewallConfigFilename)) { File.Delete(szFirewallDirectory + "\\" + szFirewallConfigFilename); }
                                File.WriteAllText(szFirewallDirectory + "\\" + szFirewallConfigFilename, szFirewallResponse);
                            }
                            catch (Exception Step4)
                            {

                                Console.WriteLine("[ERROR] Step 4 Write Configuration Failure"); 
                                continue;
                            }
                            //Clean up the files Step 5
                            
                            DirectoryInfo dirInfo = new DirectoryInfo(szFirewallDirectory);
                            FileInfo[] configs = dirInfo.GetFiles(fireWall.RemoteHost + "_*.xml");
                            if (configs.Length > fireWall.BackupCopies)
                            {
                                while(configs.Length > fireWall.BackupCopies)
                                {
                                    // Sort by creation-time descending 
                                    Array.Sort(configs, delegate (FileInfo f1, FileInfo f2)
                                    {
                                        return f2.CreationTime.CompareTo(f1.CreationTime);
                                    });
                                    configs[configs.Length - 1].Delete();
                                    configs = dirInfo.GetFiles(fireWall.RemoteHost + "_*.xml");
                                }   
                            }
                            Console.WriteLine("[INFO] BACKUP OK!");
                        }
                    }
                }
            }   
        }
        static string GetCsrfMagic(string Response)
        {
            const string csrf_marker = "name='__csrf_magic' value=";
            string szResult = "";
            if (Response.Contains(csrf_marker))
            {
                try
                {
                    string szParse = Response.Substring(Response.IndexOf(csrf_marker));
                    Regex regExCsrf1 = new Regex(@"(s)(i)(d)(:)(\w*)(,)(\d*)(;)(i)(p)(:)(\w*)(,)(\d*)");
                    Regex regExCsrf2 = new Regex(@"(s)(i)(d)(:)(\w*)(,)(\d*)");
                    Match regExMatch1 = regExCsrf1.Match(szParse);
                    Match regExMatch2 = regExCsrf2.Match(szParse);
                    if (regExMatch1.Success)
                        szResult = regExMatch1.Value;
                    else if (regExMatch2.Success)
                        szResult = regExMatch2.Value;
                    else
                        szResult = "";
                }
                catch
                {

                    szResult = "";
                }
            }
            return szResult;
        }
        static string GetSafeFileName(string name, char replace = '_')
        {
            char[] invalids = Path.GetInvalidFileNameChars();
            return new string(name.Select(c => invalids.Contains(c) ? replace : c).ToArray());
        }
    }
    public static class DataProtectionExtensions
    {
        public static string PfEncrypt(this string objText, string objKeycode)
        {
            try
            {
                byte[] objInitVectorBytes = Encoding.UTF8.GetBytes("HR$2pIjHR$2pIj12");
                byte[] objPlainTextBytes = Encoding.UTF8.GetBytes(objText);
                Rfc2898DeriveBytes objPassword = new Rfc2898DeriveBytes(objKeycode, objInitVectorBytes);
                byte[] objKeyBytes = objPassword.GetBytes(256 / 8);
                Aes objSymmetricKey = Aes.Create();
                objSymmetricKey.Mode = CipherMode.CBC;
                ICryptoTransform objEncryptor = objSymmetricKey.CreateEncryptor(objKeyBytes, objInitVectorBytes);
                MemoryStream objMemoryStream = new MemoryStream();
                CryptoStream objCryptoStream = new CryptoStream(objMemoryStream, objEncryptor, CryptoStreamMode.Write);
                objCryptoStream.Write(objPlainTextBytes, 0, objPlainTextBytes.Length);
                objCryptoStream.FlushFinalBlock();
                byte[] objEncrypted = objMemoryStream.ToArray();
                objMemoryStream.Dispose();
                objCryptoStream.Dispose();
                return Convert.ToBase64String(objEncrypted);
            }
            catch { return ""; }
        }
        public static string PfDecrypt(this string EncryptedText, string Key)
        {
            try
            {
                byte[] objInitVectorBytes = Encoding.ASCII.GetBytes("HR$2pIjHR$2pIj12");
                byte[] objDeEncryptedText = Convert.FromBase64String(EncryptedText);
                Rfc2898DeriveBytes objPassword = new Rfc2898DeriveBytes(Key, objInitVectorBytes);
                byte[] objKeyBytes = objPassword.GetBytes(256 / 8);
                Aes objSymmetricKey = Aes.Create();
                objSymmetricKey.Mode = CipherMode.CBC;
                ICryptoTransform objDecryptor = objSymmetricKey.CreateDecryptor(objKeyBytes, objInitVectorBytes);
                MemoryStream objMemoryStream = new MemoryStream(objDeEncryptedText);
                CryptoStream objCryptoStream = new CryptoStream(objMemoryStream, objDecryptor, CryptoStreamMode.Read);
                byte[] objPlainTextBytes = new byte[objDeEncryptedText.Length];
                int objDecryptedByteCount = objCryptoStream.Read(objPlainTextBytes, 0, objPlainTextBytes.Length);
                objMemoryStream.Dispose();
                objCryptoStream.Dispose();
                return Encoding.UTF8.GetString(objPlainTextBytes, 0, objDecryptedByteCount);
            }
            catch { return ""; }
        }
    }
}
