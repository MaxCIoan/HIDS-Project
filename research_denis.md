## On Processes

### 1. How do you get a full picture of what is running on a system?
To obtain a comprehensive overview of active processes using only native tools, we rely on the `ps` (process status) utility. The standard professional command is:

* `ps aux`:
    * `a`: Shows processes for all users.
    * `u`: Displays the user/owner of the process and resource usage (CPU/RAM).
    * `x`: Shows processes not attached to a terminal (daemons, background services).

For a structural view, `ps -ef` or `ps fax` (forest view) is used to visualize parent-child relationships. This is crucial for identifying **process tree injection**, where a suspicious process is spawned by a legitimate parent (like `www-data` spawning a `bash` shell).

---

### 2. What makes a process look suspicious?
Detection goes beyond the process name, as attackers often rename malicious binaries to look like system tasks (e.g., `kworker` or `systemd`). We evaluate suspicion based on four pillars:

| Indicator | Suspicious Attribute |
| :--- | :--- |
| **Path (Binary Location)** | Processes running from "world-writable" or temporary directories like `/tmp`, `/dev/shm`, or `/var/tmp`. Legitimate binaries should reside in `/usr/bin`, `/usr/sbin`, etc. |
| **Ownership (User)** | A web server user (`www-data` or `apache`) owning an interactive shell (`sh`, `bash`) or a high-privilege process running under a low-privilege user account. |
| **Resource Usage** | Sudden, sustained spikes in CPU or RAM without a known business reason, which could indicate cryptominers or data exfiltration compression. |
| **Hidden Processes** | A process that appears in `/proc` but is hidden from the `ps` command (often an indicator of a **rootkit**). |
| **Orphan Processes** | A process whose parent has died (PPID 1) unexpectedly, which may be a technique to bypass session monitoring. |

---

### 3. Where does Linux store live process information?
The source of truth for all process information in Linux is the **`/proc` file system**.

* **Definition**: It is a "pseudo-filesystem" (Virtual File System) that acts as an interface to the kernel's internal data structures. It does not exist on the disk; it exists in memory.
* **Structure**: Every running process has a directory named after its Process ID (PID). For example, `/proc/1234/`.
* **Key Files inside `/proc/[PID]/`**:
    * `/proc/[PID]/exe`: A symbolic link to the actual executable file on the disk.
    * `/proc/[PID]/cmdline`: The full command line used to start the process (including arguments).
    * `/proc/[PID]/status`: A human-readable file containing the process state, UID/GID, and memory usage.
    * `/proc/[PID]/environ`: The environment variables set for that process.
    * `/proc/[PID]/fd/`: A directory containing links to every file or network socket the process has open.