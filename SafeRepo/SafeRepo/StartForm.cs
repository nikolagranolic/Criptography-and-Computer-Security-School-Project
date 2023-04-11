using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Newtonsoft.Json;
using static System.Net.Mime.MediaTypeNames;

namespace SafeRepo
{
    internal class StartForm
    {
        private Dictionary<string, string> usernamePasswordCollection = new();
        private Dictionary<string, string> serialNumberUsernameCollection = new();  

        public void StartOptions()
        {
            Console.WriteLine("--------------------------------------------");
            Console.WriteLine("SafeRepo - your safe place for all your data");
            Console.WriteLine("--------------------------------------------");
            Console.WriteLine("          (Press enter to continue)         ");
            Console.ReadLine();
            string option;
            bool loop = true;
            do
            {
                Console.Clear();
                Console.WriteLine("Choose an option (1 - Login, 2 - Register, 3 - Exit)");
                option = Console.ReadLine();
                switch (option)
                {
                    case "1":
                        int code = Login();
                        if (code == 0)
                        {
                            loop = false;
                        }
                        else if (code == 1)
                        {
                            Console.Clear();
                            //Revoke certificate function
                            var indexBytes = File.ReadAllBytes(SafeRepo.rootDir + "CA\\index.txt");
                            var crlnumberBytes = File.ReadAllBytes(SafeRepo.rootDir + "CA\\crlnumber");
                            byte[] crlBytes = null;
                            if (File.Exists(SafeRepo.rootDir + "CA\\crl\\rootcrl.pem"))
                            {
                                crlBytes = File.ReadAllBytes(SafeRepo.rootDir + "CA\\crl\\rootcrl.pem");
                            }
                            RevokeCertificate();
                            string tmp = "";
                            do
                            {
                                Console.WriteLine("Unsuccessful login. Your certificate has been revoked. Please register again (1) or enter your credentials to restore your certificate (2).");
                                tmp = Console.ReadLine();
                            } while (tmp != "1" && tmp != "2");
                            if (tmp == "2")
                            {
                                bool success = CheckCredentials();
                                if (success)
                                {
                                    File.WriteAllBytes(SafeRepo.rootDir + "CA\\index.txt", indexBytes);
                                    File.WriteAllBytes(SafeRepo.rootDir + "CA\\crlnumber", crlnumberBytes);
                                    if (crlBytes == null)
                                    {
                                        File.Delete(SafeRepo.rootDir + "CA\\crl\\rootcrl.pem");
                                    }
                                    else
                                    {
                                        File.WriteAllBytes(SafeRepo.rootDir + "CA\\crl\\rootcrl.pem", crlBytes);
                                    }
                                    Console.WriteLine("Certificate successfully restored! Press enter to continue.");
                                    Console.ReadLine();
                                }
                                
                            }

                            SafeRepo.loggedUser = null;
                        }
                        
                        break;
                    case "2":
                        if (Register())
                        {
                            Console.WriteLine("Registration successful. You may now log in.\nPress enter to go to main menu.");
                            Console.ReadLine();
                        }
                        else
                        {
                            Console.WriteLine("Unsuccessful registration. Please try again.");
                        }
                        break;
                    case "3":
                        loop = false;
                        SafeRepo.shouldExit = true;
                        break;
                    default:
                        Console.WriteLine("Unsupported option.");
                        break;
                }
            } while (loop);
        }

        private bool Register()
        {
            string json;
            if (File.Exists(SafeRepo.rootDir + "usernamesAndPasswords")) // in case there is a usernamesAndPasswords file
            {
                json = File.ReadAllText(SafeRepo.rootDir + "usernamesAndPasswords");
                usernamePasswordCollection = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            }
            if (File.Exists(SafeRepo.rootDir + "serialNumbersAndUsernames")) // in case there is a serialNumbersAndUsernames file
            {
                json = File.ReadAllText(SafeRepo.rootDir + "serialNumbersAndUsernames");
                serialNumberUsernameCollection = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            }

            User user = new();
            Console.Clear();
            Console.WriteLine("REGISTER\nType your new username (lowercase letters only!):");
            user.username = Console.ReadLine();
            if (CheckIfUsernameTaken(user.username))
            {
                return false;
            }
            Console.WriteLine("Type your new password:");
            user.password = Console.ReadLine();
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "passwd -salt 12 " + user.password,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.WaitForExit();
            user.password = process.StandardOutput.ReadToEnd(); // hashed password
            Console.WriteLine("Type the path of your private key:");
            string keyPath = Console.ReadLine();
            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "req -new -key " + SafeRepo.rootDir + keyPath + " -config " + SafeRepo.rootDir +
                    "CA\\openssl.cnf -out " + SafeRepo.rootDir + "CA\\requests\\req_"
                    + user.username + ".csr",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = false,
                }
            };
            process.Start();
            process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();

            string certificatePath = "";

            if (output != null) // request made successfully
            {
                certificatePath = "CA\\certs\\" + user.username + "_cert.pem";
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = "ca -in " + SafeRepo.rootDir + "CA\\requests\\req_" + user.username + ".csr" +
                        " -out " + SafeRepo.rootDir + certificatePath + 
                        " -config " + SafeRepo.rootDir + "CA\\openssl.cnf -key sigurnost -batch",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                };
                process.Start();
                process.WaitForExit();
                output = process.StandardOutput.ReadToEnd();

                if (output != null) // request signed successfully
                {
                    usernamePasswordCollection.Add(user.username, user.password);
                    Console.WriteLine("Your certificate path: " + certificatePath);
                    //create user's dir
                    Directory.CreateDirectory(SafeRepo.rootDir + "UserDirs\\" + user.username);
                }
            }

            //Extracting the serial number of the certificate that is used for authentication
            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "x509 -in " + SafeRepo.rootDir + certificatePath + " -noout -text",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            //process.WaitForExit();
            output = process.StandardOutput.ReadToEnd();

            int startIndex = output.IndexOf("Serial Number: ") + "Serial Number: ".Length;
            int endIndex = output.IndexOf(" ", startIndex);
            string serialNumberString = output.Substring(startIndex, endIndex - startIndex);

            serialNumberUsernameCollection.Add(serialNumberString, user.username);

            try
            {
                json = JsonConvert.SerializeObject(usernamePasswordCollection);
                File.WriteAllText(SafeRepo.rootDir + "usernamesAndPasswords", json);
            }
            catch (IOException e)
            {
                Console.WriteLine("An error occurred while writing the file: " + e.Message);
            }
            try
            {
                json = JsonConvert.SerializeObject(serialNumberUsernameCollection);
                File.WriteAllText(SafeRepo.rootDir + "serialNumbersAndUsernames", json);
            }
            catch (IOException e)
            {
                Console.WriteLine("An error occurred while writing the file: " + e.Message);
            }
            return true;
        }

        private int Login()
        {
            string json;
            if (File.Exists(SafeRepo.rootDir + "usernamesAndPasswords")) // in case there is a usernamesAndPasswords file
            {
                json = File.ReadAllText(SafeRepo.rootDir + "usernamesAndPasswords");
                usernamePasswordCollection = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            }
            if (File.Exists(SafeRepo.rootDir + "serialNumbersAndUsernames")) // in case there is a serialNumbersAndUsernames file
            {
                json = File.ReadAllText(SafeRepo.rootDir + "serialNumbersAndUsernames");
                serialNumberUsernameCollection = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            }

            Console.Clear();
            Console.WriteLine("LOGIN");
            User user = new();
            SafeRepo.loggedUser = user;
            string output = "";
            do
            {
                Console.WriteLine("Type the path of your certificate:");
                user.certificatePath = Console.ReadLine();
                // validate cerficate
                var process1 = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = "verify -CAfile " + SafeRepo.rootDir + "CA\\rootca.pem -verbose " +
                        SafeRepo.rootDir + user.certificatePath,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                };
                process1.Start();
                process1.WaitForExit();
                output = process1.StandardOutput.ReadToEnd();
                if (output.Contains("OK"))
                {
                    if (CheckIfCertificateRevoked())
                    {
                        Console.Write("Certificate is revoked. Press enter to continue and please try again.");
                        Console.ReadLine();
                        return 2;
                    }
                    break;
                }
                else
                {
                    Console.WriteLine("Certificate not issued by trusted CA, please try again.");
                }
            } while (true);

            //Extracting the serial number of the certificate that is used for authentication
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "x509 -in " + SafeRepo.rootDir + SafeRepo.loggedUser.certificatePath + " -noout -text",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            //process.WaitForExit();
            output = process.StandardOutput.ReadToEnd();

            int startIndex = output.IndexOf("Serial Number: ") + "Serial Number: ".Length;
            int endIndex = output.IndexOf(" ", startIndex);
            string serialNumberString = output.Substring(startIndex, endIndex - startIndex);

            for (int i = 0; i < 3; i++)
            {
                Console.WriteLine("Tries remaining: " + (3 - i));

                Console.WriteLine("Type your username:");
                user.username = Console.ReadLine();
                Console.WriteLine("Type your password:");
                user.password = Console.ReadLine();
                if (serialNumberUsernameCollection[serialNumberString] != user.username)
                {
                    Console.WriteLine("Those credentials do not belong to the certificate owner! Press enter to continue...");
                    Console.ReadLine();
                }
                else if (CheckIfUsernameTaken(user.username))
                {
                    process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "openssl",
                            Arguments = "passwd -salt 12 " + user.password,
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        }
                    };
                    process.Start();
                    process.WaitForExit();
                    output = process.StandardOutput.ReadToEnd(); // hashed password

                    if (usernamePasswordCollection[user.username] == output)
                    {
                        Console.WriteLine("Enter your private key path:");
                        user.privateKeyPath = Console.ReadLine();
                        SafeRepo.loggedUser = user;
                        return 0;
                    }
                    else
                    {
                        Console.WriteLine("Wrong credentials, please try again.");
                    }
                }
                else
                {
                    Console.WriteLine("Wrong credentials, please try again.");
                }
            }

            return 1;
        }

        private bool CheckIfUsernameTaken(string username)
        {
            return usernamePasswordCollection.ContainsKey(username);
        }

        private void RevokeCertificate()
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "ca -revoke " + SafeRepo.rootDir + SafeRepo.loggedUser.certificatePath +
                    " -key sigurnost -config " + SafeRepo.rootDir + "CA\\openssl.cnf -crl_reason certificateHold",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.WaitForExit();

            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "ca " +
                    " -key sigurnost -config " + SafeRepo.rootDir + "CA\\openssl.cnf -crl_reason certificateHold"
                    + " -gencrl -out " + SafeRepo.rootDir + "CA\\crl\\rootcrl.pem",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.WaitForExit();

        }

        private bool CheckCredentials()
        {
            Console.WriteLine("Type your username.");
            var username = Console.ReadLine();
            Console.WriteLine("Type your password.");
            var password = Console.ReadLine();
            if (CheckIfUsernameTaken(username))
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = "passwd -salt 12 " + password,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                };
                process.Start();
                process.WaitForExit();
                var output = process.StandardOutput.ReadToEnd(); // hashed password
                if (usernamePasswordCollection[username] == output)
                {
                    return true;
                }
                else
                {
                    Console.WriteLine("Wrong credentials, please try again.");
                }
            }
            else
            {
                Console.WriteLine("Wrong credentials, please try again.");
            }

            return false;
        }

        private bool CheckIfCertificateRevoked()
        {
            //Extracting the serial number of the certificate that is used for authentication
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "x509 -in " + SafeRepo.rootDir + SafeRepo.loggedUser.certificatePath + " -noout -text",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            //process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();

            int startIndex = output.IndexOf("Serial Number: ") + "Serial Number: ".Length;
            int endIndex = output.IndexOf(" ", startIndex);
            string serialNumberString = output.Substring(startIndex, endIndex - startIndex);
            int serialNumber = int.Parse(serialNumberString);
            
            //Checking if that serial number is on the CRL
            var process1 = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "crl -in " + SafeRepo.rootDir + "CA\\crl\\rootcrl.pem" + " -noout -text",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process1.Start();
            //process1.WaitForExit();
            output = process1.StandardOutput.ReadToEnd();
            int startIndexCRL = 0;
            do
            {
                startIndexCRL = output.IndexOf("Serial Number: ", startIndexCRL);
                if (startIndexCRL == -1)
                {
                    break;
                }
                startIndexCRL += "Serial Number: ".Length;
                int endIndexCRL = output.IndexOf(" ", startIndexCRL);
                if (endIndexCRL == -1)
                {
                    endIndex = output.Length;
                }
                string serialNumberCRLString = output.Substring(startIndexCRL, endIndexCRL - startIndexCRL).Trim();
                int serialNumberCRL = Convert.ToInt32(serialNumberCRLString, 16);

                if (serialNumber == serialNumberCRL)
                {
                    return true;
                }
            } while (true);

            return false;
        }
    }
}
