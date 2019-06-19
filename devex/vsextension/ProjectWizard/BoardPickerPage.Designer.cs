// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
namespace OpenEnclaveSDK
{
    partial class BoardPickerPage
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.boardGrapeboard = new System.Windows.Forms.RadioButton();
            this.boardQemuArm32 = new System.Windows.Forms.RadioButton();
            this.boardOther = new System.Windows.Forms.RadioButton();
            this.label1 = new System.Windows.Forms.Label();
            this.button1 = new System.Windows.Forms.Button();
            this.panel1 = new System.Windows.Forms.Panel();
            this.boardQemuArm64 = new System.Windows.Forms.RadioButton();
            this.boardNone = new System.Windows.Forms.RadioButton();
            this.button2 = new System.Windows.Forms.Button();
            this.panel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // boardGrapeboard
            // 
            this.boardGrapeboard.AutoSize = true;
            this.boardGrapeboard.Checked = true;
            this.boardGrapeboard.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.boardGrapeboard.Location = new System.Drawing.Point(37, 46);
            this.boardGrapeboard.Name = "boardGrapeboard";
            this.boardGrapeboard.Size = new System.Drawing.Size(629, 33);
            this.boardGrapeboard.TabIndex = 0;
            this.boardGrapeboard.TabStop = true;
            this.boardGrapeboard.Text = "Scalys SES-LS1012A (Grapeboard) [AArch64/ARMv8-A]";
            this.boardGrapeboard.UseVisualStyleBackColor = true;
            // 
            // boardQemuArm32
            // 
            this.boardQemuArm32.AutoSize = true;
            this.boardQemuArm32.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.boardQemuArm32.Location = new System.Drawing.Point(37, 102);
            this.boardQemuArm32.Name = "boardQemuArm32";
            this.boardQemuArm32.Size = new System.Drawing.Size(349, 33);
            this.boardQemuArm32.TabIndex = 1;
            this.boardQemuArm32.Text = "QEMU (Emulated) [ARMv7-A]";
            this.boardQemuArm32.UseVisualStyleBackColor = true;
            // 
            // boardOther
            // 
            this.boardOther.AutoSize = true;
            this.boardOther.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.boardOther.Location = new System.Drawing.Point(37, 214);
            this.boardOther.Name = "boardOther";
            this.boardOther.Size = new System.Drawing.Size(94, 33);
            this.boardOther.TabIndex = 2;
            this.boardOther.Text = "Other";
            this.boardOther.UseVisualStyleBackColor = true;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(30, 26);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(407, 29);
            this.label1.TabIndex = 3;
            this.label1.Text = "Select the board to compile code for:";
            // 
            // button1
            // 
            this.button1.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button1.Location = new System.Drawing.Point(35, 446);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(330, 45);
            this.button1.TabIndex = 4;
            this.button1.Text = "OK";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.boardQemuArm64);
            this.panel1.Controls.Add(this.boardNone);
            this.panel1.Controls.Add(this.boardQemuArm32);
            this.panel1.Controls.Add(this.boardOther);
            this.panel1.Controls.Add(this.boardGrapeboard);
            this.panel1.Location = new System.Drawing.Point(35, 75);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(675, 345);
            this.panel1.TabIndex = 6;
            // 
            // boardQemuArm64
            // 
            this.boardQemuArm64.AutoSize = true;
            this.boardQemuArm64.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.boardQemuArm64.Location = new System.Drawing.Point(37, 158);
            this.boardQemuArm64.Name = "boardQemuArm64";
            this.boardQemuArm64.Size = new System.Drawing.Size(445, 33);
            this.boardQemuArm64.TabIndex = 4;
            this.boardQemuArm64.Text = "QEMU (Emulated) [AArch64/ARMv8-A]";
            this.boardQemuArm64.UseVisualStyleBackColor = true;
            // 
            // boardNone
            // 
            this.boardNone.AutoSize = true;
            this.boardNone.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.boardNone.Location = new System.Drawing.Point(37, 270);
            this.boardNone.Name = "boardNone";
            this.boardNone.Size = new System.Drawing.Size(216, 33);
            this.boardNone.TabIndex = 3;
            this.boardNone.Text = "None (SGX only)";
            this.boardNone.UseVisualStyleBackColor = true;
            // 
            // button2
            // 
            this.button2.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.button2.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.button2.Location = new System.Drawing.Point(380, 446);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(330, 45);
            this.button2.TabIndex = 7;
            this.button2.Text = "Cancel";
            this.button2.UseVisualStyleBackColor = true;
            // 
            // BoardPickerPage
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.button2;
            this.ClientSize = new System.Drawing.Size(742, 512);
            this.ControlBox = false;
            this.Controls.Add(this.button2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.panel1);
            this.Controls.Add(this.button1);
            this.MinimizeBox = false;
            this.Name = "BoardPickerPage";
            this.Text = "ARM Board Selection";
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.RadioButton boardGrapeboard;
        private System.Windows.Forms.RadioButton boardQemuArm32;
        private System.Windows.Forms.RadioButton boardOther;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.RadioButton boardNone;
        private System.Windows.Forms.RadioButton boardQemuArm64;
        private System.Windows.Forms.Button button2;
    }
}
