//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using System.Media;
//using System.Text.RegularExpressions;
//using System.Threading.Tasks;
//using System.Windows.Forms;
//using vcs_gxt_pseudo_comms_helper.Properties;

//namespace GtaVcsGxtSimple
//{
//    class Program
//    {
//        // Ищет присвоение переменной строкового литерала, вытягивает контент между кавычками
//        private static readonly Regex CodeStringRegex = new Regex(
//            @"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*""(?<key>[A-Za-z0-9_]+)""",
//            RegexOptions.Compiled);

//        //// Ищет строку вида [KEY] или [KEY:EXTRA], где EXTRA — любая непробельная последовательность до ]
//        //private static readonly Regex GxtKeyRegex = new Regex(
//        //    @"^\s*\[(?<key>[A-Za-z0-9_]+)(?::(?<extra>[^\]\r\n]+))?\]\s*$",
//        //    RegexOptions.Compiled);

//        static async void Play(int res_id)
//        {
//            await Task.Run(() =>
//            {
//                switch (res_id)
//                {
//                    case 0:
//                    {
//                        new SoundPlayer(Resources._2).Play(); // :/
//                        break;
//                    }
//                }
//            });
//        }

//        static void frompseudo()
//        {
//            //---------------------------------------------------------------------------
//            // Читаем все строки: из файла, если указан путь, иначе — из консоли
//            string[] decompiledLines;
//            //if (args.Length > 0 && File.Exists(args[0]))
//            //{
//            //    decompiledLines = File.ReadAllLines(args[0]);
//            //}
//            //else
//            {
//                Console.WriteLine("Вставьте текст (код + GXT-блоки), завершите ввод Ctrl+Z:");
//                var input = new List<string>();
//                string line;
//                while ((line = Console.ReadLine()) != null) { input.Add(line); }
//                decompiledLines = input.ToArray();
//            }
//            List<(int, string)> codeKeys = new List<(int, string)>(); // ida row code, parsed key (string)
//            for (int i = 0; i < decompiledLines.Length; i++)
//            {
//                var m = CodeStringRegex.Match(decompiledLines[i]);
//                if (m.Success)
//                    codeKeys.Add((i + 1, m.Groups["key"].Value)); // +1 ida начинает код с 1 строчки
//            }
//            //---------------------------------------------------------------------------



//            //---------------------------------------------------------------------------
//            string[] gxtLines = File.ReadAllLines("vcs_ENGLISH.txt"); // https://github.com/Sergeanur/GXT/blob/master/VCS%20PS2/ENGLISH.txt
//            var results = new List<(int LineNumber, string Key, string Text)>();

//            // 4) Для каждой строки исходника ищем метку GXT и берем текст из gxtLines
//            foreach (var c in codeKeys)
//            {
//                for (int i = 0; i < gxtLines.Length; i++)
//                {
//                    if (gxtLines[i].Trim().ToLower().StartsWith("[" + c.Item2.Trim().ToLower())) // our key
//                    {
//                        for (int j = i + 1; j < gxtLines.Length; j++) // search key string. skip comments. etc
//                        {
//                            if ((gxtLines[j].Trim() != "") && !(gxtLines[j].StartsWith("["))) { results.Add((c.Item1, c.Item2, gxtLines[j].Trim())); break; }
//                        }
//                        break;
//                    }
//                }
//            }
//            //---------------------------------------------------------------------------



//            //---------------------------------------------------------------------------
//            // Выводим
//            Console.Clear();
//            if (results.Count == 0)
//            {
//                Console.WriteLine("Совпадений GXT-ключей не найдено.");
//            }
//            else
//            {
//                Console.WriteLine("Найденные GXT-блоки:");
//                foreach (var (ln, key, txt) in results) { string s = $"{ln,4}: {key},  {txt}"; Console.WriteLine(s); File.AppendAllText("out.txt", s + "\r\n"); }
//            }
//            //---------------------------------------------------------------------------

//        }

//        static void livetranslategxt()
//        {
//            string lastClipboard = Clipboard.ContainsText() ? Clipboard.GetText() : "";
//            string[] gxtLines = File.ReadAllLines("vcs_ENGLISH.txt"); // https://github.com/Sergeanur/GXT/blob/master/VCS%20PS2/ENGLISH.txt
//            if (gxtLines.Length == 0) { return; }
//            while (true)
//            {
//                try
//                {
//                    if (Clipboard.ContainsText())
//                    {
//                        string text = Clipboard.GetText();
//                        if (!string.Equals(text, lastClipboard) && text.Trim() != "")
//                        {
//                            lastClipboard = text;
//                            //----------------------------------------------------- (on change text)

//                            Match m = CodeStringRegex.Match(text.Trim());
//                            if (m.Success) { text = m.Groups["key"].Value.Trim(); }
//                            else { text = text.Replace("\"", "").Replace("'", "").Trim(); }

//                            if (text != "")
//                            {
//                                for (int i = 0; i < gxtLines.Length; i++)
//                                {
//                                    if (gxtLines[i].Trim().ToLower().StartsWith("[" + text.Trim().ToLower())) // our key
//                                    {
//                                        for (int j = i + 1; j < gxtLines.Length; j++) // search key string. skip comments. etc
//                                        {
//                                            if ((gxtLines[j].Trim() != "") && !(gxtLines[j].StartsWith("[")))
//                                            {
//                                                string out_text = gxtLines[j].Trim();
//                                                Clipboard.SetText(out_text);
//                                                Console.WriteLine($"{text} => {out_text}");
//                                                lastClipboard = out_text;
//                                                Play(0);
//                                                break;
//                                            }
//                                        }
//                                        break;
//                                    }
//                                }
//                            }

//                            //-----------------------------------------------------
//                        }
//                    }
//                }
//                catch { }
//                System.Threading.Thread.Sleep(1000);
//            }
//        }

//        static void livetranslatesimple()
//        {
//            string lastClipboard = Clipboard.ContainsText() ? Clipboard.GetText() : "";
//            while (true)
//            {
//                try
//                {
//                    if (Clipboard.ContainsText())
//                    {
//                        string text = Clipboard.GetText();
//                        if (!string.Equals(text, lastClipboard) && text.Trim() != "")
//                        {
//                            lastClipboard = text;
//                            //----------------------------------------------------- (on change text)


//                            string out_text = $"LUA_{text.Replace("\"", "").Replace(" ", "").Replace("#", "").Trim()}";
//                            Clipboard.SetText(out_text);
//                            Console.WriteLine($"{text} => {out_text}");
//                            lastClipboard = out_text;
//                            Play(0);
//                            return;

//                            //-----------------------------------------------------
//                        }
//                    }
//                }
//                catch { }
//                System.Threading.Thread.Sleep(10);
//            }
//        }

//        [STAThread] // для clipboard
//        static void Main(string[] args)
//        {
//            //frompseudo();
//            //livetranslategxt();
//            while(true)
//            livetranslatesimple();
//        }
//    }
//}













































using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Media;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using vcs_gxt_pseudo_comms_helper.Properties;

public class Program
{
    static void Main()
    {
        ClipboardForm.Init();
        var thread = new Thread(ClipboardWorker);
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();

        Console.WriteLine("Нажмите Enter для выхода...");
        Console.ReadLine();
    }

    static void ClipboardWorker()
    {
        Application.Run(new ClipboardForm());
    }
}


class ClipboardForm : Form
{
    private string _lastClipboard = "";
    public static List<string> mi = new List<string>();
    public static List<string> psp = new List<string>();
    public static List<(int, string)> musor = new List<(int, string)>();

    public static void Init()
    {
        { // psp proto finder
            string dir = "psp";
            List<string> files = GetAllFiles(dir);
            //Console.WriteLine($"files: {files.Count}");
            foreach (string f in files)
                psp.AddRange(File.ReadAllLines(f).ToList());
            //Console.WriteLine($"psp: {psp.Count}");
        }

        // old
        {
            mi = File.ReadAllLines("mi.txt").ToList();
            Console.WriteLine($"cnt: {mi.Count}");
            string[] muLines = File.ReadAllLines("musor.txt");
            foreach (var line in muLines)
            {
                var parts = line.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && int.TryParse(parts[0], out int num))
                    musor.Add((num, parts[1]));
            }
        }
    }

    public ClipboardForm()
    {
        // Регистрация на уведомления об изменении буфера обмена
        NativeMethods.AddClipboardFormatListener(this.Handle);
        this.Enabled = false;
    }

    protected override void WndProc(ref Message m)
    {
        const int WM_CLIPBOARDUPDATE = 0x031D;
        if (m.Msg == WM_CLIPBOARDUPDATE)
        {
            TryProcessClipboard();
        }
        base.WndProc(ref m);
    }

    private string Modify1(string input)
    {
        // 1) Prefix GetPhrase with AudioManager.
        //    (?<![\w.]) ensures we don't touch Already.AudioManager.GetPhrase or MyGetPhrase methods.
        var result = Regex.Replace(
            input,
            @"(?<![\w.])GetPhrase",
            "AudioManager.GetPhrase");

        // 2) Prefix GetGenericMaleTalkSfx with AudioManager.
        result = Regex.Replace(
            result,
            @"(?<![\w.])GetGeneric",
            "AudioManager.GetGeneric");

        // 3) Capture PS2_SFX_ID( ... ) up to the first ')'
        //    This pattern grabs everything inside the parentheses in group 1.
        result = Regex.Replace(
            result,
            @"PS2_SFX_ID\(([^)]*)\)",
            m =>
            {
            // m.Groups[1].Value is the inner argument.
            // Here you could transform it if you wanted; for now we just re‑insert it.
            var inner = m.Groups[1].Value;
                return $"{inner}";
            });

        return result;
    }

    private string Find(List<string> rows, string s)
    {
        foreach (string ls in rows)
        {
            if (ls.ToLower().Contains(s.ToLower()) && ls.Contains(";"))
                return ls.Trim();
        }
        return s;
    }

    private void TryProcessClipboard()
    {
        if (Clipboard.ContainsText())
        {
            var text = Clipboard.GetText().Trim(); // trim убрать то ломает
            if (text.Trim() != "" && text.Trim() != _lastClipboard)
            {
                //string outText = $"LUA_{text.Replace("\"", "").Replace(" ", "").Replace("#", "")}";
                string outText = $"{text.Replace("\"", "").Replace(" ", "").Replace("#", "")}";
                //outText = $"_ZN{"cPedCommentsManager".Length}cPedCommentsManager{outText.Length}{outText}Ev"; // lazy mangler

                // int to mi
                ////Match match = Regex.Match(outText, @"^\d+$");
                //Match match = Regex.Match(text, @"\d+");
                //if (match.Success && int.Parse(match.Value) < mi.Count)
                //    outText = mi[int.Parse(match.Value)];
                //else
                //    return;

                // mi to mang
                //Match match = Regex.Match(text, @"MI_(\w+)");
                //if (match.Success)
                //    outText = match.Value;
                //else
                //    return;

                //// sub_ to mang
                //int midx = -1;
                //foreach (var lnk in musor)
                //{
                //    if (lnk.Item2.ToLower() == outText.ToLower())
                //        midx = lnk.Item1;
                //}
                //if (midx < 0)
                //    return;
                //outText = mi[midx];

                //// mi to mang
                //{
                //    int midx = -1;
                //    for (int i = 0; i < mi.Count; i++)
                //    {
                //        if (mi[i].ToLower().Contains(outText.ToLower()))
                //            midx = i;
                //    }
                //    if (midx < 0)
                //        return;
                //    outText = mi[midx];
                //    Console.WriteLine($"{mi[midx]}    {midx}");
                //}
                ////else
                ////    return;

                //outText = outText.Replace("MI_", "");
                //outText = $"_ZN{"cPedCommentsManager".Length}cPedCommentsManager{outText.Length+10}Get{outText}TalkSfxEv"; // lazy mangler

                // some getphrase
                //outText = Modify1(text);

                outText = $"LUA_{text.Replace("\"", "").Replace(" ", "").Replace("#", "").Trim()}";
                outText = $"mp_lsn_{text.Replace("\"", "").Replace(" ", "").Replace("#", "").Trim()}";
                //outText = $"{text.Replace("void ", "int ")}";
                //outText = $"{Find(psp, $"{text.Replace("int __cdecl ", "").Replace("()", "").Trim()}(")}";
                string str = "CBmx";
                outText = $"{text.Replace("_ZN8CVehicle", $"_ZN{str.Length}{str}")}";
                outText = $"{outText.Replace("_ZN5CBike", $"_ZN{str.Length}{str}")}";

                Clipboard.SetText(outText);
                Console.WriteLine($"{text} => {outText}");
                _lastClipboard = outText;
                Play(0);
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        NativeMethods.RemoveClipboardFormatListener(this.Handle);
        base.Dispose(disposing);
    }

    static async void Play(int res_id)
    {
        await Task.Run(() =>
        {
            switch (res_id)
            {
                case 0:
                    {
                        new SoundPlayer(Resources._2).Play(); // :/
                        break;
                    }
            }
        });
    }


    static List<string> GetAllFiles(string folderPath)
    {
        List<string> fileList = new List<string>();
        try
        {
            string[] files = Directory.GetFiles(folderPath);
            fileList.AddRange(files);
            string[] subDirectories = Directory.GetDirectories(folderPath);
            foreach (string subDirectory in subDirectories)
            {
                fileList.AddRange(GetAllFiles(subDirectory));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка при обработке папки {folderPath}: {ex.Message}");
        }

        return fileList;
    }
}

static class NativeMethods
{
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    public static extern bool AddClipboardFormatListener(IntPtr hwnd);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    public static extern bool RemoveClipboardFormatListener(IntPtr hwnd);
}