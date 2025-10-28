#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import subprocess
import os
import re
import sys
import ctypes

class BlogPublisher:
    def __init__(self, root):
        self.root = root
        self.root.title("Hugo博客发布工具")
        self.root.geometry("900x700")

        # 配置路径
        self.posts_dir = r"C:\HDisk\Hugo\loft\content\posts"
        self.git_dir = r"C:\HDisk\Hugo\loft"

        self.create_widgets()

    def create_widgets(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Title输入
        ttk.Label(main_frame, text="标题 (Title):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.title_entry = ttk.Entry(main_frame, width=70)
        self.title_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        # Date输入
        ttk.Label(main_frame, text="日期 (Date):").grid(row=1, column=0, sticky=tk.W, pady=5)
        date_frame = ttk.Frame(main_frame)
        date_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        self.date_entry = ttk.Entry(date_frame, width=30)
        self.date_entry.grid(row=0, column=0, sticky=tk.W)
        self.date_entry.insert(0, "留空则使用当前时间")
        self.date_entry.config(foreground='gray')

        # 为date_entry添加焦点事件
        self.date_entry.bind('<FocusIn>', self.on_date_focus_in)
        self.date_entry.bind('<FocusOut>', self.on_date_focus_out)

        ttk.Button(date_frame, text="使用当前时间", command=self.set_current_time).grid(row=0, column=1, padx=5)
        ttk.Label(date_frame, text="(格式: 2025-10-25T16:44:53+08:00)", font=('Arial', 8)).grid(row=0, column=2)

        # Tags输入
        ttk.Label(main_frame, text="标签 (Tags):").grid(row=2, column=0, sticky=tk.W, pady=5)
        tags_frame = ttk.Frame(main_frame)
        tags_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        self.tags_entry = ttk.Entry(tags_frame, width=70)
        self.tags_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        ttk.Label(tags_frame, text="(用逗号分隔，如: kernel, game security, inject)", font=('Arial', 8)).grid(row=1, column=0, sticky=tk.W)

        # Commit reason输入
        ttk.Label(main_frame, text="提交说明:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.commit_entry = ttk.Entry(main_frame, width=70)
        self.commit_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.commit_entry.insert(0, "发布新文章")

        # Markdown内容输入
        ttk.Label(main_frame, text="Markdown内容:").grid(row=4, column=0, sticky=(tk.W, tk.N), pady=5)

        # 使用ScrolledText创建可滚动的文本框
        self.content_text = scrolledtext.ScrolledText(main_frame, width=70, height=20, wrap=tk.WORD)
        self.content_text.grid(row=4, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=5)

        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="清空内容", command=self.clear_all).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="预览", command=self.preview_post).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="发布", command=self.publish_post, style='Accent.TButton').grid(row=0, column=2, padx=5)

        # 配置网格权重
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

    def on_date_focus_in(self, event):
        if self.date_entry.get() == "留空则使用当前时间":
            self.date_entry.delete(0, tk.END)
            self.date_entry.config(foreground='black')

    def on_date_focus_out(self, event):
        if not self.date_entry.get():
            self.date_entry.insert(0, "留空则使用当前时间")
            self.date_entry.config(foreground='gray')

    def set_current_time(self):
        current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
        self.date_entry.delete(0, tk.END)
        self.date_entry.insert(0, current_time)
        self.date_entry.config(foreground='black')

    def clear_all(self):
        if messagebox.askyesno("确认", "确定要清空所有内容吗？"):
            self.title_entry.delete(0, tk.END)
            self.date_entry.delete(0, tk.END)
            self.date_entry.insert(0, "留空则使用当前时间")
            self.date_entry.config(foreground='gray')
            self.tags_entry.delete(0, tk.END)
            self.commit_entry.delete(0, tk.END)
            self.commit_entry.insert(0, "发布新文章")
            self.content_text.delete(1.0, tk.END)

    def parse_tags(self, tags_str):
        """解析tags字符串，返回列表格式"""
        if not tags_str:
            return []
        # 分割标签并去除空白
        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()]
        return tags

    def generate_hugo_content(self):
        """生成Hugo格式的博客内容"""
        title = self.title_entry.get().strip()
        if not title:
            raise ValueError("标题不能为空")

        # 处理日期
        date_input = self.date_entry.get().strip()
        if not date_input or date_input == "留空则使用当前时间":
            date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
        else:
            date = date_input

        # 处理tags
        tags_str = self.tags_entry.get().strip()
        tags = self.parse_tags(tags_str)
        tags_formatted = ', '.join([f'"{tag}"' for tag in tags])

        # 获取Markdown内容
        content = self.content_text.get(1.0, tk.END).strip()
        if not content:
            raise ValueError("内容不能为空")

        # 生成Hugo格式
        hugo_content = f"""+++
title = '{title}'
date = {date}
categories = []
tags = [{tags_formatted}]
+++

{content}
"""
        return hugo_content, title

    def preview_post(self):
        """预览生成的博客内容"""
        try:
            hugo_content, _ = self.generate_hugo_content()

            # 创建预览窗口
            preview_window = tk.Toplevel(self.root)
            preview_window.title("预览")
            preview_window.geometry("800x600")

            # 创建文本框显示预览内容
            preview_text = scrolledtext.ScrolledText(preview_window, wrap=tk.WORD)
            preview_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            preview_text.insert(1.0, hugo_content)
            preview_text.config(state=tk.DISABLED)

        except ValueError as e:
            messagebox.showerror("错误", str(e))

    def sanitize_filename(self, title):
        """清理文件名，移除非法字符"""
        # 移除或替换Windows文件名中的非法字符
        illegal_chars = r'[<>:"/\\|?*]'
        filename = re.sub(illegal_chars, '', title)
        # 替换空格为下划线
        filename = filename.replace(' ', '-')
        return filename

    def publish_post(self):
        """发布博客"""
        try:
            # 生成内容
            hugo_content, title = self.generate_hugo_content()

            # 生成文件名
            filename = self.sanitize_filename(title) + ".md"
            filepath = os.path.join(self.posts_dir, filename)

            # 确认是否覆盖
            if os.path.exists(filepath):
                if not messagebox.askyesno("文件已存在", f"文件 {filename} 已存在，是否覆盖？"):
                    return

            # 写入文件
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(hugo_content)

            messagebox.showinfo("成功", f"文章已保存到: {filepath}")

            # 询问是否执行Git提交
            if messagebox.askyesno("Git提交", "是否立即执行Git提交？"):
                self.git_commit()

        except ValueError as e:
            messagebox.showerror("错误", str(e))
        except Exception as e:
            messagebox.showerror("错误", f"发布失败: {str(e)}")

    def git_commit(self):
        """执行Git提交"""
        try:
            commit_message = self.commit_entry.get().strip()
            if not commit_message:
                commit_message = "发布新文章"

            # 切换到git目录
            os.chdir(self.git_dir)

            # 执行git命令
            commands = [
                ["git", "add", "."],
                ["git", "commit", "-m", commit_message],
                ["git", "push", "origin", "main"]
            ]

            output_messages = []

            for cmd in commands:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8'
                )

                cmd_str = ' '.join(cmd)
                output_messages.append(f"执行: {cmd_str}")

                # 处理标准输出
                if result.stdout:
                    output_messages.append(f"{result.stdout.strip()}")

                # 处理标准错误（Git常将正常信息也输出到stderr）
                if result.stderr:
                    stderr_text = result.stderr.strip()
                    # 只有真正的错误才标记为错误（returncode != 0）
                    if result.returncode != 0:
                        output_messages.append(f"错误: {stderr_text}")
                    else:
                        # returncode = 0 时，stderr 中的内容是正常信息或警告
                        output_messages.append(f"{stderr_text}")

                # 检查命令是否执行失败
                if result.returncode != 0:
                    # 如果是commit命令且没有更改，不算错误
                    if "git commit" in cmd_str and ("nothing to commit" in result.stdout or "nothing to commit" in result.stderr):
                        output_messages.append("提示: 没有需要提交的更改")
                        continue
                    else:
                        raise Exception(f"命令执行失败: {cmd_str}\n返回码: {result.returncode}\n{result.stderr}")

            # 显示所有输出
            messagebox.showinfo("Git提交成功", "\n".join(output_messages))

        except Exception as e:
            messagebox.showerror("Git提交失败", str(e))

def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """以管理员权限重新运行脚本"""
    try:
        if sys.platform == 'win32':
            # 获取当前Python解释器和脚本路径
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:])

            # 使用ShellExecute以管理员权限运行
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                params,
                None,
                1  # SW_SHOWNORMAL
            )
            return True
    except Exception as e:
        messagebox.showerror("权限提升失败", f"无法以管理员权限运行: {str(e)}")
        return False

def main():
    # 检查管理员权限
    if not is_admin():
        print("检测到非管理员权限，正在请求管理员权限...")
        if run_as_admin():
            sys.exit(0)  # 关闭当前非管理员进程
        else:
            # 如果权限提升失败，询问是否继续
            root = tk.Tk()
            root.withdraw()  # 隐藏主窗口
            if not messagebox.askyesno("权限警告",
                                       "未能获取管理员权限，Git操作可能会失败。\n是否继续运行？"):
                sys.exit(1)
            root.destroy()

    root = tk.Tk()
    app = BlogPublisher(root)
    root.mainloop()

if __name__ == "__main__":
    main()
