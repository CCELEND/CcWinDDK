#include "ProcessTree.h"

// 释放进程树
void free_process_tree(ProcessTreeNode* node)
{
    if (!node) return;

    for (size_t i = 0; i < node->child_count; i++) {
        free_process_tree(node->children[i]);
    }
    free(node->children);
    free(node);

}


// 构建进程树
ProcessTreeNode* build_process_tree(DWORD pid)
{
    ProcessTreeNode* root = create_process_node(pid);
    if (!root) return NULL;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        free(root);
        return NULL;
    }

    // 第一次遍历：收集所有进程信息
    DWORD processes[1024]{};
    DWORD parent_pids[1024]{};
    size_t process_count = 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(PROCESSENTRY32);

    // 收集进程信息
    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        free(root);
        return NULL;
    }

    do {
        if (process_count >= 1024) break;
        processes[process_count] = pe.th32ProcessID;
        parent_pids[process_count] = pe.th32ParentProcessID;
        process_count++;
    } while (Process32Next(hSnapshot, &pe));

    // 构建进程树，只处理直接子进程
    for (size_t i = 0; i < process_count; i++) {
        if (parent_pids[i] != pid) continue;

        // 重新分配子节点数组
        ProcessTreeNode** new_children = (ProcessTreeNode**)realloc(
            root->children, (root->child_count + 1) * sizeof(ProcessTreeNode*));

        if (!new_children) continue;

        root->children = new_children;
        ProcessTreeNode* child_node = create_process_node(processes[i]);

        if (!child_node) continue;

        root->children[root->child_count] = child_node;
        root->child_count++;
    }

    CloseHandle(hSnapshot);
    return root;
}

// 暂停进程树
BOOL suspend_process_tree(ProcessTreeNode* node)
{
    if (!node) return FALSE;

    BOOL success = TRUE;

    // 先暂停子进程
    for (size_t i = 0; i < node->child_count; i++)
    {
        if (!suspend_process_tree(node->children[i])) {
            success = FALSE;
        }
    }

    // 暂停当前进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, node->pid);
    if (hProcess) {
        if (!DebugActiveProcess(node->pid)) {
            fprintf(stderr, "    [-] Failed to suspend process: %d\n", node->pid);
            success = FALSE;
        }
        else {
            printf("    [+] Suspended process: %d\n", node->pid);
        }
        CloseHandle(hProcess);
    }
    else {
        fprintf(stderr, "    [-] Failed to open process: %d (Error: %lu)\n", node->pid, GetLastError());
        success = FALSE;
    }

    return success;
}

// 恢复进程树
BOOL resume_process_tree(ProcessTreeNode* node) {
    if (!node) return FALSE;

    BOOL success = TRUE;

    // 恢复当前进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, node->pid);
    if (hProcess) {
        if (!DebugActiveProcessStop(node->pid)) {
            fprintf(stderr, "    [-] Failed to resume process: %d\n", node->pid);
            success = FALSE;
        }
        else {
            printf("    [+] Resumed process: %d\n", node->pid);
        }
        CloseHandle(hProcess);
    }
    else {
        fprintf(stderr, "    [-] Failed to open process: %d (Error: %lu)\n", node->pid, GetLastError());
        success = FALSE;
    }

    // 恢复子进程
    for (size_t i = 0; i < node->child_count; i++) {
        if (!resume_process_tree(node->children[i])) {
            success = FALSE;
        }
    }

    return success;
}