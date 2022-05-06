use nix::{
    libc::user_regs_struct,
    sys::{
        personality::{self, Persona},
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{execvp, fork, ForkResult, Pid},
};
use std::{
    error::Error,
    ffi::{c_void, CString},
};

/// デバッガ内の情報
pub struct DbgInfo {
    pid: Pid,
    brk_addr: Option<*mut c_void>, // ブレークポイントのアドレス
    brk_val: i64,                  // ブレークポイントを設定したメモリの元の値
    filename: String,              // 実行ファイル
}

/// デバッガ
/// ZDbg<Running>は子プロセスを実行中
/// ZDbg<NotRunning>は子プロセスは実行していない
pub struct ZDbg<T> {
    info: Box<DbgInfo>,
    _state: T,
}

/// デバッガの実装
pub struct Running; // 実行中
pub struct NotRunning; // 実行していない

/// デバッガの実装の列挙型表現。Exitの場合終了
pub enum State {
    Running(ZDbg<Running>),
    NotRunning(ZDbg<NotRunning>),
    Exit,
}

/// RunningとNotRunningで共通の実装
impl<T> ZDbg<T> {
    /// ブレークポイントのアドレスを設定する関数。子プロセスのメモリ上には反映しない。
    /// アドレス設定に成功した場合はtrueを返す
    fn set_break_addr(&mut self, cmd: &[&str]) -> bool {
        if self.info.brk_addr.is_some() {
            eprintln!(
                "<<ブレークポイントは設定済みです：Addr = {:p}>>",
                self.info.brk_addr.unwrap()
            );
            false
        } else if let Some(addr) = get_break_addr(cmd) {
            self.info.brk_addr = Some(addr); // ブレークポイントのアドレスを保存
            true
        } else {
            false
        }
    }

    /// 共通のコマンドを実行
    fn do_cmd_common(&self, cmd: &[&str]) {
        match cmd[0] {
            "help" | "h" => do_help(),
            _ => (),
        }
    }
}

/// NotRunning時に呼び出し可能なメソッド
impl ZDbg<NotRunning> {
    pub fn new(filename: String) -> Self {
        ZDbg {
            info: Box::new(DbgInfo {
                pid: Pid::from_raw(0),
                brk_addr: None,
                brk_val: 0,
                filename,
            }),
            _state: NotRunning,
        }
    }

    /// ブレークポイントを設定
    fn do_break(&mut self, cmd: &[&str]) -> bool {
        self.set_break_addr(cmd)
    }

    /// 子プロセスを生成し、成功した場合はRunning状態に遷移
    fn do_run(mut self, cmd: &[&str]) -> Result<State, Box<dyn Error>> {
        // 子プロセスに渡すコマンドライン引数
        let args: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();

        match unsafe { fork()? } {
            ForkResult::Child => {
                // ASLRを無効に
                let p = personality::get().unwrap();
                personality::set(p | Persona::ADDR_NO_RANDOMIZE).unwrap();
                ptrace::traceme().unwrap();

                // exec
                execvp(&CString::new(self.info.filename.as_str()).unwrap(), &args).unwrap();
                unreachable!();
            }
            ForkResult::Parent { child, .. } => match waitpid(child, None)? {
                WaitStatus::Stopped(..) => {
                    println!("<<子プロセスの実行に成功しました：PID = {child}>>");
                    self.info.pid = child;
                    let mut dbg = ZDbg::<Running> {
                        info: self.info,
                        _state: Running,
                    };
                    dbg.set_break()?; // ブレークポイントを設定
                    dbg.do_continue()
                }
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    Err("子プロセスの実行に失敗しました".into())
                }
                _ => Err("子プロセスが不正な状態です".into()),
            },
        }
    }

    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, Box<dyn Error>> {
        if cmd.is_empty() {
            return Ok(State::NotRunning(self));
        }

        match cmd[0] {
            "run" | "r" => return self.do_run(cmd),
            "break" | "b" => {
                self.do_break(cmd);
            }
            "exit" => return Ok(State::Exit),
            "continue" | "c" | "stepi" | "s" | "registers" | "regs" => {
                eprintln!("<<ターゲットを実行していません。runで実行してください>>")
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::NotRunning(self))
    }
}

/// Running時に呼び出し可能なメソッド
impl ZDbg<Running> {
    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, Box<dyn Error>> {
        if cmd.is_empty() {
            return Ok(State::Running(self));
        }

        match cmd[0] {
            "break" | "b" => self.do_break(cmd)?,
            "continue" | "c" => return self.do_continue(),
            "registers" | "regs" => {
                let regs = ptrace::getregs(self.info.pid)?;
                print_regs(&regs);
            }
            "stepi" | "s" => return self.do_stepi(),
            "run" | "r" => eprintln!("<<既に実行中です>>"),
            "exit" => {
                self.do_exit()?;
                return Ok(State::Exit);
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::Running(self))
    }

    /// exitを実行。実行中のプロセスはkill
    fn do_exit(self) -> Result<(), Box<dyn Error>> {
        loop {
            ptrace::kill(self.info.pid)?;
            match waitpid(self.info.pid, None)? {
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => return Ok(()),
                _ => (),
            }
        }
    }

    /// ブレークポイントを実際に設定
    /// つまり、該当アドレスのメモリを"int 3" = 0xccに設定
    fn set_break(&mut self) -> Result<(), Box<dyn Error>> {
        let addr = if let Some(addr) = self.info.brk_addr {
            addr
        } else {
            return Ok(());
        };

        // TODO:
        //
        // addrの位置にブレークポイントを設定せよ

        Err("TODO".into())
    }

    /// breakを実行
    fn do_break(&mut self, cmd: &[&str]) -> Result<(), Box<dyn Error>> {
        if self.set_break_addr(cmd) {
            self.set_break()?;
        }
        Ok(())
    }

    /// stepiを実行。機械語レベルで1行実行
    fn do_stepi(self) -> Result<State, Box<dyn Error>> {
        // TODO: ここを実装せよ
        //
        // 次の実行アドレスがブレークポイントの場合、
        // 先に、0xccに書き換えたメモリを元に戻す必要がある
        // また、0xccを元に戻してステップ実行して、再度ブレークポイントを設定する必要がある (step_and_breakを呼び出すとよい)
        //
        // 次の実行アドレスがブレークポイントではない場合は、ptrace::stepとwait_childを呼び出すのみでよい

        Err("TODO".into())
    }

    /// ブレークポイントで停止していた場合は
    /// 1ステップ実行しブレークポイントを再設定
    fn step_and_break(mut self) -> Result<State, Box<dyn Error>> {
        // TODO: ここを実装せよ
        //
        // 停止した位置がブレークポイントの場合、
        // 1ステップ機械語レベルで実行しwaitpidで待機
        // その後、再度ブレークポイントを設定
        //
        // ブレークポイントでない場合は何もしない

        Ok(State::Running(self))
    }

    /// continueを実行
    fn do_continue(self) -> Result<State, Box<dyn Error>> {
        // ブレークポイントで停止していた場合は1ステップ実行後再設定
        match self.step_and_break()? {
            State::Running(r) => {
                // 実行再開
                ptrace::cont(r.info.pid, None)?;
                r.wait_child()
            }
            n => Ok(n),
        }
    }

    /// 子プロセスをwait。子プロセスが終了した場合はNotRunning状態に遷移
    fn wait_child(self) -> Result<State, Box<dyn Error>> {
        match waitpid(self.info.pid, None)? {
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                println!("<<子プロセスが終了しました>>");
                let not_run = ZDbg::<NotRunning> {
                    info: self.info,
                    _state: NotRunning,
                };
                Ok(State::NotRunning(not_run))
            }
            WaitStatus::Stopped(..) => {
                // TODO: ここを実装せよ
                //
                // 停止したアドレスがブレークポイントのアドレスかを調べ
                // ブレークポイントの場合は以下を行う
                // - プログラムカウンタを1減らす
                // - 0xccに書き換えたメモリを元の値に戻す

                Ok(State::Running(self))
            }
            _ => Err("waitpidの返り値が不正です".into()),
        }
    }
}

/// ヘルプを表示
fn do_help() {
    println!(
        r#"コマンド一覧 (括弧内は省略記法)
break 0x8000 : ブレークポイントを0x8000番地に設定 (b 0x8000)
run          : プログラムを実行 (r)
continue     : プログラムを再開 (c)
stepi        : 機械語レベルで1ステップ実行 (s)
registers    : レジスタを表示 (regs)
exit         : 終了
help         : このヘルプを表示 (h)"#
    );
}

/// レジスタを表示
fn print_regs(regs: &user_regs_struct) {
    println!(
        r#"RIP: {:#016x}, RSP: {:#016x}, RBP: {:#016x}
RAX: {:#016x}, RBX: {:#016x}, RCX: {:#016x}
RDX: {:#016x}, RSI: {:#016x}, RDI: {:#016x}
 R8: {:#016x},  R9: {:#016x}, R10: {:#016x}
R11: {:#016x}, R12: {:#016x}, R13: {:#016x}
R14: {:#016x}, R15: {:#016x}"#,
        regs.rip,
        regs.rsp,
        regs.rbp,
        regs.rax,
        regs.rbx,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
        regs.r12,
        regs.r13,
        regs.r14,
        regs.r15,
    );
}

/// コマンドからブレークポイントを計算
fn get_break_addr(cmd: &[&str]) -> Option<*mut c_void> {
    if cmd.len() < 2 {
        eprintln!("<<アドレスを指定してください\n例：break 0x8000>>");
        return None;
    }

    let addr_str = cmd[1];
    if &addr_str[0..2] != "0x" {
        eprintln!("<<アドレスは16進数でのみ指定可能です\n例：break 0x8000>>");
        return None;
    }

    let addr = match usize::from_str_radix(&addr_str[2..], 16) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("<<アドレス変換エラー：{}>>", e);
            return None;
        }
    } as *mut c_void;

    Some(addr)
}
