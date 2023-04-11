using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SafeRepo
{
    internal class FileManipulator
    {
        public static void SplitFile(string inputFile, string destDir, int numOfChunks, string encPassword)
        {
            Console.WriteLine("Type your private key password:");
            string pKeyPass = Console.ReadLine();
            int chunkSize = (int)Math.Ceiling((double)new FileInfo(inputFile).Length / numOfChunks);
            int bytesRead;
            byte[] buffer = new byte[chunkSize];
            FileStream sourceStream = new FileStream(inputFile, FileMode.Open);
            Directory.CreateDirectory(destDir + Path.GetFileName(inputFile));
            string symAlgorithm = "aes256";
            Process process;
            for (int i = 1; i <= numOfChunks; i++)
            {
                Directory.CreateDirectory(destDir + Path.GetFileName(inputFile) + "\\part" + i);
                using (FileStream targetStream =
                    new FileStream(destDir + Path.GetFileName(inputFile) + "\\part" + i + "\\part", FileMode.Create))
                {
                    while ((bytesRead = sourceStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        targetStream.Write(buffer, 0, bytesRead);
                        if (targetStream.Length >= chunkSize) break;
                    }
                    targetStream.Close();
                }
                string fileName = destDir + Path.GetFileName(inputFile) + "\\part" + i + "\\part";

                // signing the part of the file
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = "dgst -sha1 -out " +
                        fileName + ".signed -passin pass:" + pKeyPass + " -sign " +
                        SafeRepo.rootDir + SafeRepo.loggedUser.privateKeyPath + " " + fileName,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                };
                process.Start();
                process.WaitForExit();
                // encryption with symmetric algorithm
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = "enc -" + symAlgorithm + " -in " + fileName +
                        " -out " + fileName + ".enc -nosalt -k " + encPassword,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                };
                process.Start();
                process.WaitForExit();
                var output = process.StandardOutput.ReadToEnd();
                File.Delete(fileName);
            }

            //kreiranje digitalne anvelope
            string filePath = destDir + Path.GetFileName(inputFile) + "\\digitalEnvelope";
            string symAlgToWrite = symAlgorithm;
            string decPassToWrite = encPassword;
            using (FileStream fs = File.Open(filePath, FileMode.OpenOrCreate))
            using (StreamWriter sw = new StreamWriter(fs))
            {
                sw.WriteLine(symAlgToWrite);
                sw.WriteLine(decPassToWrite);
            }
            //izdvajanje javnog kljuca
            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "rsa -in " + SafeRepo.rootDir + SafeRepo.loggedUser.privateKeyPath +
                    " -pubout -passin pass:" + pKeyPass + " -out " + destDir + Path.GetFileName(inputFile) + "\\pub.key",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.WaitForExit();
            //kriptovanje digitalne envelope
            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "rsautl -encrypt" +
                    " -in " + filePath +
                    " -inkey " + destDir + Path.GetFileName(inputFile) + "\\pub.key -pubin" +
                    " -out " + filePath + ".enc",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.WaitForExit();
            //brisanje fajla sa javnim kljucem i fajla digotalEnvelope
            File.Delete(destDir + Path.GetFileName(inputFile) + "\\pub.key");
            File.Delete(destDir + Path.GetFileName(inputFile) + "\\digitalEnvelope");
            sourceStream.Close();
        }

        public static void MergeFile(string fileName, string destination) //returns true if successful, returns false if someone has had unauthorized access
        {
            Console.WriteLine("Type your private key password:");
            string pKeyPass = Console.ReadLine();

            //first we have to open digital envelope
            string digEnvFileName = SafeRepo.rootDir + "UserDirs\\" + SafeRepo.loggedUser.username + "\\" + fileName + "\\digitalEnvelope";
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "rsautl -decrypt" +
                    " -in " + digEnvFileName + ".enc" +
                    " -inkey " + SafeRepo.rootDir + SafeRepo.loggedUser.privateKeyPath +
                    " -passin pass:" + pKeyPass + " -out " + digEnvFileName + ".dec",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.WaitForExit();

            string[] lines = File.ReadAllLines(digEnvFileName + ".dec");
            string symAlgorithm = lines[0];
            string encPassword = lines[1];
            File.Delete(digEnvFileName + ".dec");

            string fileDir = SafeRepo.rootDir + "UserDirs\\" + SafeRepo.loggedUser.username + "\\" + fileName;
            string[] fileParts = Directory.GetDirectories(fileDir);
            Array.Sort(fileParts);

            int bytesRead;
            byte[] buffer = new byte[1024];

            using (FileStream targetStream = new FileStream(destination, FileMode.Create))
            {
                foreach (string filePart in fileParts)
                {
                    //dekripcija dijela
                    process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "openssl",
                            Arguments = "enc -" + symAlgorithm + " -in " + filePart +
                            "\\part.enc -out " + filePart + "\\part.dec -nosalt -d -k " + encPassword,
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        }
                    };
                    process.Start();
                    process.WaitForExit();
                    //izdvajanje javnog kljuca
                    process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "openssl",
                            Arguments = "rsa -in " + SafeRepo.rootDir + SafeRepo.loggedUser.privateKeyPath +
                            " -pubout -passin pass:" + pKeyPass +
                            " -out " + filePart + "\\pub.key",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        }
                    };
                    process.Start();
                    process.WaitForExit();
                    //verifikacija potpisa
                    process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "openssl",
                            Arguments = "dgst -sha1 -verify " + filePart + "\\pub.key" +
                            " -signature " + filePart + "\\part.signed " +
                            filePart + "\\part.dec",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        }
                    };
                    process.Start();
                    process.WaitForExit();
                    var output = process.StandardOutput.ReadToEnd();
                    if (output.Contains("Failure"))
                    {
                        Console.WriteLine("--------------------------------------------------");
                        Console.WriteLine("WARNING: Unauthorized access to the file detected.");
                        Console.WriteLine("The original content of the file is probably lost.");
                        Console.WriteLine("Press enter to continue...");
                        Console.WriteLine("--------------------------------------------------");
                        Console.ReadLine();
                    }

                    using (FileStream sourceStream = new FileStream(filePart + "\\part.dec", FileMode.Open))
                    {
                        while ((bytesRead = sourceStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            targetStream.Write(buffer, 0, bytesRead);
                        }
                    }

                    File.Delete(filePart + "\\part.dec");
                    File.Delete(filePart + "\\pub.key");
                }
            }
        }
    }
}
