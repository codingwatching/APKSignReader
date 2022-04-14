using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.IO.Compression;

namespace APKSignReader
{
    public partial class Form1 : Form
    {
        private SignedCms signedCms;
        public Form1()
        {
            InitializeComponent();
        }

        private void textBox1_DragEnter(object sender, DragEventArgs e)
        {
            e.Effect = DragDropEffects.Copy;
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files != null && files.Length != 0)
            {
                textBox1.Text = files[0];
            }
        }

        private void textBox1_DragLeave(object sender, DragEventArgs e)
        {
            e.Effect = DragDropEffects.None;
        }

        private void textBox1_DragDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop, false) == true)
            {
                e.Effect = DragDropEffects.All;

                parseSignatures();
            }
        }
        private void button1_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                textBox1.Text = openFileDialog1.FileName;
                parseSignatures();
            }
        }
        private void parseSignatures()
        {
            try
            {
                using (ZipArchive archive = ZipFile.OpenRead(textBox1.Text))
                {
                    foreach (var entry in archive.Entries)
                    {
                        if (entry.Name.Contains(".DSA") || entry.Name.Contains(".RSA"))
                        {
                            byte[] b;
                            using (Stream stream = entry.Open())
                            {
                                using (var ms = new MemoryStream())
                                {
                                    stream.CopyTo(ms);
                                    b = ms.ToArray();
                                }
                            }

                            signedCms = new SignedCms();
                            signedCms.Decode(b);

                            richTextBox1.Text = "";
                            foreach (SignerInfo signerInfo in signedCms.SignerInfos)
                            {                          
                                X509Certificate2 cert = new X509Certificate2(signerInfo.Certificate.RawData);
                                richTextBox1.Text += "Signer: " + cert.Subject + "\r\n";
                                richTextBox1.Text += "Signature Algorithm: " + signerInfo.DigestAlgorithm.FriendlyName + "\r\n";
                                richTextBox1.Text += "Signature: " + BitConverter.ToString(signerInfo.GetSignature()) + "\r\n";
                                richTextBox1.Text += "\r\n";
                            }

                            formatSignatures();
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                richTextBox2.Text = "Not a valid APK file!";
            }
        }
        
        private void formatSignatures()
        {
            var certs = signedCms.Certificates;

            if (radioButton1.Checked) {
                Stream stream = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stream);

                writer.Write(certs.Count);
                foreach (var cert in certs)
                {
                    writer.Write(cert.RawData.Length);
                    writer.Write(cert.RawData);
                }

                byte[] bytes = new byte[stream.Length];
                stream.Position = 0;
                stream.Read(bytes, 0, (int)stream.Length);

                richTextBox2.Text = Convert.ToBase64String(bytes);
                writer.Close();
                stream.Close();
            }
            if (radioButton2.Checked) {
                Stream stream = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stream);

                writer.Write(certs.Count);
                foreach (var cert in certs)
                {
                    writer.Write(cert.RawData.Length);
                    writer.Write(cert.RawData);
                }

                byte[] bytes = new byte[stream.Length];
                stream.Position = 0;
                stream.Read(bytes, 0, (int)stream.Length);

                richTextBox2.Text = BitConverter.ToString(bytes).Replace("-", " ");
                writer.Close();
                stream.Close();
            }
            if (radioButton3.Checked)
            {
                StringBuilder sb = new StringBuilder();
                sb.Append("std::vector<std::vector<uint8_t>> apk_signatures {");
                for (int i = 0; i < certs.Count; i++)
                {
                    sb.Append("{");
                    byte[] cert = certs[i].RawData;
                    for (int j = 0; j < cert.Length; j++)
                    {
                        sb.Append("0x" + cert[j].ToString("X2"));
                        if (j != cert.Length - 1)
                        {
                            sb.Append(", ");
                        }
                    }
                    sb.Append("}");
                    if (i != certs.Count - 1)
                    {
                        sb.Append(", ");
                    }
                }
                sb.Append("};");
                richTextBox2.Text = sb.ToString();
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            formatSignatures();
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            formatSignatures();
        }

        private void radioButton3_CheckedChanged(object sender, EventArgs e)
        {
            formatSignatures();
        }
    }
}
