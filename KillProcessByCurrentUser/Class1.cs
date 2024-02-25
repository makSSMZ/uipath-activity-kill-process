using System;
using System.Activities;
using System.ComponentModel;
using System.Security.Principal;
using System.Security.Authentication;
using System.Diagnostics;
using System.Management;
using System.Linq;

namespace QIWI.Processes
{
    public class KillCurrentUserProcess : CodeActivity
    {
        [Category("Input")]
        [Description("Enter process name")]
        [DisplayName("ProcessName")]
        [RequiredArgument]
        public InArgument<string> ProcessName { get; set; }

        protected override void Execute(CodeActivityContext context)
        {
            var processName = ProcessName.Get(context);
            var processOwner = string.Empty;
            try
            {
                string userName = null;

                WindowsIdentity user = WindowsIdentity.GetCurrent();
                if (user == null)
                    throw new InvalidCredentialException(@"No current user?");
                userName = user.Name;
                var processFinder = new ManagementObjectSearcher(string.Format("Select * from Win32_Process where Name = '{0}'", processName + ".exe"));

                var processes = processFinder.Get();
                if (processes.Count == 0)
                    return;
                foreach (ManagementObject managementObject in processes)
                {
                    var pId = Convert.ToInt32(managementObject["ProcessId"]);
                    var process = Process.GetProcessById(pId);
                    var processOwnerInfo = new object[2];
                    managementObject.InvokeMethod("GetOwner", processOwnerInfo);
                    processOwner = (string)processOwnerInfo[0];
                    var net = (string)processOwnerInfo[1];
                    if (!string.IsNullOrEmpty(net))
                        processOwner = string.Format("{0}\\{1}", net, processOwner);
                    if (string.CompareOrdinal(processOwner, userName) == 0)
                        process.Kill();
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Не удалось убить процесс {processName} для текущего пользователя {processOwner}." +
                    $"{ex.Message}");
            }
        }



        public static void KillCurrent1UserProcess(string ProcessName)
        {
            Process.GetProcesses().AsEnumerable()
                .Where(r => r.ProcessName == ProcessName && r.StartInfo.EnvironmentVariables["username"] == Environment.UserName)
                .ToList().ForEach(r => r.Kill());
        }

    }
}
