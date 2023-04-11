using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SafeRepo
{
    internal class SafeRepo
    {
        public static User loggedUser = null;
        public static string rootDir = "..\\..\\..\\..\\..\\";
        public static bool shouldExit = false;
        private StartForm sf = new();
        public void RunApp()
        {
            do
            {
                sf.StartOptions();
                if (shouldExit) return;
                MainMenu();
            } while (!shouldExit);
        }
        private void MainMenu()
        {
            LoginSuccesful();
            string option;
            do
            {
                Console.Clear();
                MainMenuOptions();
                option = Console.ReadLine();
                switch (option)
                {
                    case "1":
                        DownloadDocument();
                        break;
                    case "2":
                        UploadDocument();
                        break;
                }
            } while (option == "1" || option == "2");

            if (option == "3")
            {
                Console.Clear();
                loggedUser = null;
                return;
            }
            else if (option == "4")
            {
                shouldExit = true;
                loggedUser = null;
                return;
            }
        }

        private void DownloadDocument()
        {
            ListAllDocuments();
            Console.WriteLine("Type the name of a document that you want to download:");
            Console.WriteLine("(or type 'x' or 'X' to cancel)");
            string fileName = Console.ReadLine();
            if (fileName == "x" || fileName == "X") { return; }
            Console.WriteLine("Type the destination where you want to download the file:");
            string destination = Console.ReadLine();
            FileManipulator.MergeFile(fileName, destination);
        }

        private void UploadDocument()
        {
            string inputFile;
            Console.Clear();
            Console.WriteLine("Enter the path of a document that you want to upload to SafeRepo:");
            Console.WriteLine("(or type 'x' or 'X' to cancel)");
            inputFile = Console.ReadLine();
            if (inputFile == "x" || inputFile == "X") { return; }

            Random rnd = new Random();
            int min = 4;
            int max = 9;
            int randomNumber = rnd.Next(min, max);

            Console.WriteLine("Enter the password for symmetric encryption:");
            string encPassword = Console.ReadLine();

            FileManipulator.SplitFile(inputFile, rootDir + "UserDirs\\" + loggedUser.username + "\\", randomNumber, encPassword);
        }

        private void LoginSuccesful()
        {
            Console.Clear();
            Console.WriteLine("Login successful! Press enter to continue...");
            Console.ReadLine();
            Console.Clear();
        }

        private void MainMenuOptions()
        {
            Console.WriteLine("---------------------------------------------------------------------------------");
            Console.WriteLine("------------------------------------MAIN MENU------------------------------------");
            Console.WriteLine("---------------------------------------------------------------------------------");
            Console.WriteLine("Choose an option (1-download document; 2-upload document; 3-sign out; 4-exit app)");
        }

        private void ListAllDocuments()
        {
            Console.Clear();
            string userDir = rootDir + "UserDirs\\" + loggedUser.username;
            var filenames = Directory.GetDirectories(userDir);
            Console.WriteLine("Here are your documents that you can download:");
            Console.WriteLine("----------------------------------------------");
            int i = 1;
            foreach (string filename in filenames)
            {
                Console.WriteLine("[" + i++ + "]" + Path.GetFileName(filename));
            }
            Console.WriteLine("----------------------------------------------");
        }
    }
}
