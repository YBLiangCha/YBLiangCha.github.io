#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from tkinter import messagebox
from datetime import datetime
import subprocess
import os
import re
import sys
import ctypes
import json
from pathlib import Path
import markdown
from html.parser import HTMLParser

def get_app_dir():
    """获取应用程序所在目录（支持打包后的exe）"""
    if getattr(sys, 'frozen', False):
        # 如果是打包后的exe
        return Path(sys.executable).parent
    else:
        # 如果是脚本运行
        return Path(__file__).parent

class HTMLToTextParser(HTMLParser):
    """将HTML转换为纯文本以便在Text widget中显示"""
    def __init__(self):
        super().__init__()
        self.text = []
        self.current_tag = None

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag

    def handle_data(self, data):
        self.text.append(data)

    def get_text(self):
        return ''.join(self.text)

class HistoryManager:
    """历史记录管理器"""
    def __init__(self, history_file="blog_history.json"):
        self.history_file = get_app_dir() / history_file
        self.history = self.load_history()

    def load_history(self):
        """加载历史记录"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_history(self):
        """保存历史记录"""
        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)

    def add_record(self, title, date, tags, content, commit_msg):
        """添加记录"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "title": title,
            "date": date,
            "tags": tags,
            "content": content,
            "commit_msg": commit_msg
        }
        self.history.insert(0, record)  # 最新的在前面
        # 只保留最近50条记录
        if len(self.history) > 50:
            self.history = self.history[:50]
        self.save_history()

    def delete_record(self, index):
        """删除记录"""
        if 0 <= index < len(self.history):
            del self.history[index]
            self.save_history()
            return True
        return False

    def get_records(self):
        """获取所有记录"""
        return self.history

class TagsManager:
    """Tags智能推荐管理器"""
    def __init__(self, tags_file="tags_stats.json"):
        self.tags_file = get_app_dir() / tags_file
        self.tags_stats = self.load_tags()

    def load_tags(self):
        """加载tags统计"""
        if self.tags_file.exists():
            try:
                with open(self.tags_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_tags(self):
        """保存tags统计"""
        with open(self.tags_file, 'w', encoding='utf-8') as f:
            json.dump(self.tags_stats, f, ensure_ascii=False, indent=2)

    def update_tags(self, tags_list):
        """更新tags使用次数"""
        for tag in tags_list:
            tag = tag.strip()
            if tag:
                self.tags_stats[tag] = self.tags_stats.get(tag, 0) + 1
        self.save_tags()

    def get_recommended_tags(self, limit=10):
        """获取推荐的tags（按使用频率排序）"""
        sorted_tags = sorted(self.tags_stats.items(), key=lambda x: x[1], reverse=True)
        return [tag for tag, count in sorted_tags[:limit]]

class ColoredLogText(ScrolledText):
    """彩色日志文本框"""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.text.configure(state='disabled', bg='#1e1e1e', fg='white', font=('Consolas', 9))

        # 配置颜色标签
        self.text.tag_config('success', foreground='#4ade80')  # 绿色
        self.text.tag_config('error', foreground='#f87171')    # 红色
        self.text.tag_config('warning', foreground='#fbbf24')  # 黄色
        self.text.tag_config('info', foreground='#60a5fa')     # 蓝色
        self.text.tag_config('normal', foreground='white')     # 白色

    def log(self, message, level='normal'):
        """添加日志"""
        self.text.configure(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {message}\n"
        self.text.insert('end', log_msg, level)
        self.text.see('end')
        self.text.configure(state='disabled')

    def clear_log(self):
        """清空日志"""
        self.text.configure(state='normal')
        self.text.delete(1.0, 'end')
        self.text.configure(state='disabled')

class BlogPublisherPro:
    def __init__(self, root):
        self.root = root
        self.root.title("Hugo博客发布工具 Pro")
        self.root.geometry("1200x800")

        # 配置路径
        self.posts_dir = r"C:\HDisk\Hugo\loft\content\posts"
        self.git_dir = r"C:\HDisk\Hugo\loft"

        # 初始化管理器
        self.history_manager = HistoryManager()
        self.tags_manager = TagsManager()

        self.create_widgets()

        # 加载推荐tags
        self.update_tags_recommendations()

    def create_widgets(self):
        """创建界面组件"""
        # 主容器 - 使用Paned Window分割
        main_paned = ttk.PanedWindow(self.root, orient='horizontal')
        main_paned.pack(fill='both', expand=True, padx=5, pady=5)

        # 左侧面板 - 输入区域
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=3)

        # 右侧面板 - 历史记录和日志
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=1)

        # 创建左侧内容
        self.create_left_panel(left_frame)

        # 创建右侧内容
        self.create_right_panel(right_frame)

    def create_left_panel(self, parent):
        """创建左侧输入面板"""
        # 使用notebook分页
        notebook = ttk.Notebook(parent)
        notebook.pack(fill='both', expand=True)

        # 编辑页面
        edit_frame = ttk.Frame(notebook)
        notebook.add(edit_frame, text='编辑文章')

        # 创建表单
        form_frame = ttk.Frame(edit_frame, padding=10)
        form_frame.pack(fill='x', padx=5, pady=5)

        # Title
        ttk.Label(form_frame, text="标题:", font=('Arial', 10, 'bold')).grid(
            row=0, column=0, sticky='w', pady=5)
        self.title_entry = ttk.Entry(form_frame, width=60, font=('Arial', 10))
        self.title_entry.grid(row=0, column=1, sticky='ew', pady=5, padx=5)

        # Date
        ttk.Label(form_frame, text="日期:", font=('Arial', 10, 'bold')).grid(
            row=1, column=0, sticky='w', pady=5)
        date_frame = ttk.Frame(form_frame)
        date_frame.grid(row=1, column=1, sticky='ew', pady=5, padx=5)

        self.date_entry = ttk.Entry(date_frame, width=25)
        self.date_entry.pack(side='left', padx=(0, 5))

        ttk.Button(date_frame, text="当前时间", command=self.set_current_time,
                  bootstyle='info-outline').pack(side='left')

        # Tags
        ttk.Label(form_frame, text="标签:", font=('Arial', 10, 'bold')).grid(
            row=2, column=0, sticky='w', pady=5)
        tags_container = ttk.Frame(form_frame)
        tags_container.grid(row=2, column=1, sticky='ew', pady=5, padx=5)

        self.tags_entry = ttk.Entry(tags_container, width=60)
        self.tags_entry.pack(fill='x')

        # Commit message
        ttk.Label(form_frame, text="提交说明:", font=('Arial', 10, 'bold')).grid(
            row=3, column=0, sticky='w', pady=5)
        self.commit_entry = ttk.Entry(form_frame, width=60)
        self.commit_entry.insert(0, "发布新文章")
        self.commit_entry.grid(row=3, column=1, sticky='ew', pady=5, padx=5)

        form_frame.columnconfigure(1, weight=1)

        # Markdown内容
        content_frame = ttk.LabelFrame(edit_frame, text="Markdown内容", padding=10)
        content_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.content_text = ScrolledText(content_frame, autohide=True, height=20)
        self.content_text.pack(fill='both', expand=True)
        self.content_text.text.configure(font=('Consolas', 10), wrap='word')

        # 按钮区域
        button_frame = ttk.Frame(edit_frame)
        button_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(button_frame, text="清空", command=self.clear_all,
                  bootstyle='secondary').pack(side='left', padx=5)
        ttk.Button(button_frame, text="预览", command=self.preview_post,
                  bootstyle='info').pack(side='left', padx=5)
        ttk.Button(button_frame, text="发布", command=self.publish_post,
                  bootstyle='success').pack(side='left', padx=5)


    def create_right_panel(self, parent):
        """创建右侧历史和日志面板"""
        # 使用notebook分页
        notebook = ttk.Notebook(parent)
        notebook.pack(fill='both', expand=True)

        # 历史记录页面
        history_frame = ttk.Frame(notebook)
        notebook.add(history_frame, text='历史记录')

        # 历史记录列表
        history_container = ttk.Frame(history_frame, padding=5)
        history_container.pack(fill='both', expand=True)

        # 创建Treeview显示历史
        self.history_tree = ttk.Treeview(history_container, columns=('title', 'date'),
                                         show='tree headings', height=15)
        self.history_tree.heading('#0', text='时间')
        self.history_tree.heading('title', text='标题')
        self.history_tree.column('#0', width=150)
        self.history_tree.column('title', width=200)
        self.history_tree.column('date', width=0, stretch=False)  # 隐藏

        scrollbar = ttk.Scrollbar(history_container, orient='vertical',
                                  command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)

        self.history_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # 历史记录按钮
        history_btn_frame = ttk.Frame(history_frame)
        history_btn_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(history_btn_frame, text="加载", command=self.load_history_item,
                  bootstyle='info-outline').pack(side='left', padx=2)
        ttk.Button(history_btn_frame, text="删除", command=self.delete_history_item,
                  bootstyle='danger-outline').pack(side='left', padx=2)
        ttk.Button(history_btn_frame, text="刷新", command=self.refresh_history,
                  bootstyle='secondary-outline').pack(side='left', padx=2)

        # 日志页面
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text='日志')

        log_container = ttk.Frame(log_frame, padding=5)
        log_container.pack(fill='both', expand=True)

        self.log_text = ColoredLogText(log_container, autohide=True)
        self.log_text.pack(fill='both', expand=True)

        # 日志按钮
        log_btn_frame = ttk.Frame(log_frame)
        log_btn_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(log_btn_frame, text="清空日志", command=self.log_text.clear_log,
                  bootstyle='secondary-outline').pack(side='left', padx=2)

        # 标签库页面
        tags_lib_frame = ttk.Frame(notebook)
        notebook.add(tags_lib_frame, text='标签库')

        # 标签库内容
        tags_lib_container = ttk.Frame(tags_lib_frame, padding=10)
        tags_lib_container.pack(fill='both', expand=True)

        # 标题和说明
        header_frame = ttk.Frame(tags_lib_container)
        header_frame.pack(fill='x', pady=(0, 10))

        ttk.Label(header_frame, text="常用标签", font=('Arial', 12, 'bold')).pack(side='left')
        ttk.Label(header_frame, text="点击标签添加到输入框", font=('Arial', 9),
                 foreground='gray').pack(side='left', padx=10)

        # 创建可滚动的标签区域
        tags_scroll_frame = ScrolledText(tags_lib_container, autohide=True)
        tags_scroll_frame.pack(fill='both', expand=True)
        tags_scroll_frame.text.configure(state='disabled')

        # 保存引用以便后续更新
        self.tags_lib_container = tags_scroll_frame.text

        # 创建一个Frame来放置标签按钮（放在Text widget内部）
        self.tags_buttons_frame = ttk.Frame(tags_scroll_frame.text)
        tags_scroll_frame.text.window_create('1.0', window=self.tags_buttons_frame)

        # 初始化时加载历史记录
        self.refresh_history()

        # 欢迎日志
        self.log_text.log("博客发布工具已启动", "success")

    def update_tags_recommendations(self):
        """更新tags推荐按钮"""
        # 清除旧的按钮
        for widget in self.tags_buttons_frame.winfo_children():
            widget.destroy()

        # 获取所有标签及其使用次数
        tags_stats = self.tags_manager.tags_stats
        if not tags_stats:
            # 如果没有标签，显示提示
            ttk.Label(self.tags_buttons_frame, text="暂无常用标签，发布文章后会自动记录",
                     font=('Arial', 10), foreground='gray').pack(pady=20)
            return

        # 按使用频率排序
        sorted_tags = sorted(tags_stats.items(), key=lambda x: x[1], reverse=True)

        # 使用网格布局显示标签按钮（每行5个）
        row = 0
        col = 0
        max_cols = 5

        for tag, count in sorted_tags:
            # 创建按钮，显示标签名和使用次数
            btn_text = f"{tag} ({count})"
            btn = ttk.Button(self.tags_buttons_frame, text=btn_text,
                           command=lambda t=tag: self.add_tag(t),
                           bootstyle='info', width=20)
            btn.grid(row=row, column=col, padx=5, pady=5, sticky='ew')

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

        # 配置列权重，使按钮能够自适应宽度
        for i in range(max_cols):
            self.tags_buttons_frame.columnconfigure(i, weight=1)


    def add_tag(self, tag):
        """添加tag到输入框"""
        current = self.tags_entry.get().strip()
        if current:
            if tag not in current.split(','):
                self.tags_entry.insert('end', f", {tag}")
        else:
            self.tags_entry.insert(0, tag)
        self.log_text.log(f"添加标签: {tag}", "info")

    def set_current_time(self):
        """设置当前时间"""
        current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
        self.date_entry.delete(0, 'end')
        self.date_entry.insert(0, current_time)
        self.log_text.log("已设置当前时间", "info")

    def clear_all(self):
        """清空所有输入"""
        self.title_entry.delete(0, 'end')
        self.date_entry.delete(0, 'end')
        self.tags_entry.delete(0, 'end')
        self.commit_entry.delete(0, 'end')
        self.commit_entry.insert(0, "发布新文章")
        self.content_text.text.delete(1.0, 'end')
        self.log_text.log("已清空所有内容", "info")

    def parse_tags(self, tags_str):
        """解析tags字符串"""
        if not tags_str:
            return []
        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()]
        return tags

    def generate_hugo_content(self):
        """生成Hugo格式内容"""
        title = self.title_entry.get().strip()
        if not title:
            self.log_text.log("错误: 标题不能为空", "error")
            raise ValueError("标题不能为空")

        # 处理日期
        date_input = self.date_entry.get().strip()
        if not date_input:
            date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
        else:
            date = date_input

        # 处理tags
        tags_str = self.tags_entry.get().strip()
        tags = self.parse_tags(tags_str)
        if not tags:
            self.log_text.log("警告: 未设置标签", "warning")
        tags_formatted = ', '.join([f'"{tag}"' for tag in tags])

        # 获取内容
        content = self.content_text.text.get(1.0, 'end').strip()
        if not content:
            self.log_text.log("错误: 内容不能为空", "error")
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
        return hugo_content, title, date, tags, content

    def preview_post(self):
        """预览文章"""
        try:
            hugo_content, title, date, tags, content = self.generate_hugo_content()

            # 创建预览窗口
            preview_window = ttk.Toplevel(self.root)
            preview_window.title("预览")
            preview_window.geometry("900x700")

            # 创建notebook用于不同预览模式
            notebook = ttk.Notebook(preview_window)
            notebook.pack(fill='both', expand=True, padx=10, pady=10)

            # Hugo源码预览
            source_frame = ttk.Frame(notebook)
            notebook.add(source_frame, text='Hugo源码')

            source_text = ScrolledText(source_frame, autohide=True)
            source_text.pack(fill='both', expand=True, padx=5, pady=5)
            source_text.text.insert(1.0, hugo_content)
            source_text.text.configure(state='disabled', font=('Consolas', 10))

            # Markdown渲染预览
            rendered_frame = ttk.Frame(notebook)
            notebook.add(rendered_frame, text='渲染预览')

            # 转换Markdown为HTML
            md = markdown.Markdown(extensions=['extra', 'codehilite', 'tables'])
            html_content = md.convert(content)

            # 由于tkinter没有直接的HTML渲染，我们使用简化的文本显示
            rendered_text = ScrolledText(rendered_frame, autohide=True)
            rendered_text.pack(fill='both', expand=True, padx=5, pady=5)

            # 简单解析HTML并显示
            parser = HTMLToTextParser()
            parser.feed(html_content)
            rendered_text.text.insert(1.0, parser.get_text())
            rendered_text.text.configure(state='disabled', font=('Arial', 11), wrap='word')

            self.log_text.log("已打开预览窗口", "success")

        except ValueError as e:
            pass  # 错误已在generate_hugo_content中记录
        except Exception as e:
            self.log_text.log(f"预览失败: {str(e)}", "error")

    def sanitize_filename(self, title):
        """清理文件名"""
        illegal_chars = r'[<>:"/\\|?*]'
        filename = re.sub(illegal_chars, '', title)
        filename = filename.replace(' ', '-')
        return filename

    def publish_post(self):
        """发布文章"""
        try:
            # 生成内容
            hugo_content, title, date, tags, content = self.generate_hugo_content()

            # 生成文件名
            filename = self.sanitize_filename(title) + ".md"
            filepath = os.path.join(self.posts_dir, filename)

            # 确认覆盖
            if os.path.exists(filepath):
                if not messagebox.askyesno("文件已存在", f"文件 {filename} 已存在，是否覆盖？"):
                    self.log_text.log("取消发布", "warning")
                    return

            # 写入文件
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(hugo_content)

            self.log_text.log(f"文章已保存: {filename}", "success")

            # 保存到历史记录
            commit_msg = self.commit_entry.get().strip() or "发布新文章"
            self.history_manager.add_record(title, date, tags, content, commit_msg)
            self.refresh_history()

            # 更新tags统计
            self.tags_manager.update_tags(tags)
            self.update_tags_recommendations()

            # 询问Git提交
            if messagebox.askyesno("Git提交", "是否立即执行Git提交？"):
                self.git_commit()

        except ValueError as e:
            pass  # 错误已记录
        except Exception as e:
            self.log_text.log(f"发布失败: {str(e)}", "error")

    def git_commit(self):
        """执行Git提交"""
        try:
            commit_message = self.commit_entry.get().strip() or "发布新文章"

            # 切换到git目录
            os.chdir(self.git_dir)

            self.log_text.log("开始Git提交...", "info")

            # 执行git命令
            commands = [
                ["git", "add", "."],
                ["git", "commit", "-m", commit_message],
                ["git", "push", "origin", "main"]
            ]

            for cmd in commands:
                cmd_str = ' '.join(cmd)
                self.log_text.log(f"执行: {cmd_str}", "info")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8'
                )

                # 处理输出
                if result.stdout:
                    self.log_text.log(result.stdout.strip(), "normal")

                if result.stderr:
                    stderr_text = result.stderr.strip()
                    if result.returncode != 0:
                        self.log_text.log(stderr_text, "error")
                    else:
                        # 正常信息或警告
                        self.log_text.log(stderr_text, "normal")

                # 检查错误
                if result.returncode != 0:
                    if "git commit" in cmd_str and ("nothing to commit" in result.stdout or "nothing to commit" in result.stderr):
                        self.log_text.log("提示: 没有需要提交的更改", "warning")
                        continue
                    else:
                        raise Exception(f"命令执行失败: {cmd_str}")

            self.log_text.log("Git提交成功!", "success")

        except Exception as e:
            self.log_text.log(f"Git提交失败: {str(e)}", "error")

    def refresh_history(self):
        """刷新历史记录列表"""
        # 清空当前列表
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        # 加载历史记录
        records = self.history_manager.get_records()
        for i, record in enumerate(records):
            timestamp = record.get('timestamp', '')
            title = record.get('title', '')
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                time_str = timestamp[:16] if timestamp else ''

            self.history_tree.insert('', 'end', iid=str(i), text=time_str,
                                    values=(title, record.get('date', '')))

        self.log_text.log(f"已加载 {len(records)} 条历史记录", "info")

    def load_history_item(self):
        """加载选中的历史记录"""
        selection = self.history_tree.selection()
        if not selection:
            self.log_text.log("请先选择一条历史记录", "warning")
            return

        try:
            index = int(selection[0])
            records = self.history_manager.get_records()

            if 0 <= index < len(records):
                record = records[index]

                # 填充到表单
                self.title_entry.delete(0, 'end')
                self.title_entry.insert(0, record.get('title', ''))

                self.date_entry.delete(0, 'end')
                self.date_entry.insert(0, record.get('date', ''))

                self.tags_entry.delete(0, 'end')
                tags = record.get('tags', [])
                if tags:
                    self.tags_entry.insert(0, ', '.join(tags))

                self.commit_entry.delete(0, 'end')
                self.commit_entry.insert(0, record.get('commit_msg', '发布新文章'))

                self.content_text.text.delete(1.0, 'end')
                self.content_text.text.insert(1.0, record.get('content', ''))

                self.log_text.log(f"已加载历史记录: {record.get('title', '')}", "success")
        except Exception as e:
            self.log_text.log(f"加载失败: {str(e)}", "error")

    def delete_history_item(self):
        """删除选中的历史记录"""
        selection = self.history_tree.selection()
        if not selection:
            self.log_text.log("请先选择一条历史记录", "warning")
            return

        if messagebox.askyesno("确认删除", "确定要删除这条历史记录吗？"):
            try:
                index = int(selection[0])
                if self.history_manager.delete_record(index):
                    self.refresh_history()
                    self.log_text.log("历史记录已删除", "success")
            except Exception as e:
                self.log_text.log(f"删除失败: {str(e)}", "error")

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
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:])

            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                params,
                None,
                1
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
            sys.exit(0)
        else:
            root = ttk.Window()
            root.withdraw()
            if not messagebox.askyesno("权限警告", "未能获取管理员权限，Git操作可能会失败。\n是否继续运行？"):
                sys.exit(1)
            root.destroy()

    # 创建应用
    root = ttk.Window(themename="darkly")  # 使用darkly主题
    app = BlogPublisherPro(root)
    root.mainloop()

if __name__ == "__main__":
    main()
