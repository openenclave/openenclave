// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenEnclaveSDK
{
    public partial class BoardPickerPage : Form
    {
        public string Board = "None";

        public BoardPickerPage()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (this.boardGrapeboard.Checked)
            {
                this.Board = "ls-ls1012grapeboard";
            }
            else if (this.boardQemuArm32.Checked)
            {
                this.Board = "vexpress-qemu_virt";
            }
            else if (this.boardQemuArm64.Checked)
            {
                this.Board = "vexpress-qemu_armv8a";
            }
            else if (this.boardOther.Checked)
            {
                this.Board = "Other";
            }

            this.DialogResult = DialogResult.OK;
            this.Close();
        }
    }
}
