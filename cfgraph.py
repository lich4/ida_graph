import functools
import networkx
import os
import threading
import traceback
from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
import uvicorn

import idc
import idaapi
import idautils
import __main__
    
def get_global(key):
    return __main__.__dict__.get("cfgraph:" + key)

def set_global(key, val):
    __main__.__dict__["cfgraph:" + key] = val

def wrap_func(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result_container = []
        def inner():
            try:
                res = func(*args, **kwargs)
                result_container.append(res)
            except Exception as e:
                print(f"\ntool exception: {e}")
                traceback.print_exc()
                result_container.append(e)
        idaapi.execute_sync(inner, idaapi.MFF_WRITE)
        if result_container and isinstance(result_container[0], Exception):
            raise result_container[0]
        return result_container[0] if result_container else None
    return wrapper
    
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "cfgraph")
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 1100

app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")

def find_all_dominance_sets(edges, start_node):
    G = networkx.DiGraph(edges)
    idom = networkx.immediate_dominators(G, start_node)
    # self excluded
    dom_tree = networkx.DiGraph((d, n) for n, d in idom.items() if n != d)
    return { # start excluded
        n: networkx.descendants(dom_tree, n) for n in dom_tree.nodes() if n != start_node
    }

def get_name(ea):
    name = idc.get_name(ea)
    if not name:
        return f"{ea:x}"
    if name.startswith("sub_"):
        return f"{ea:x}"
    else:
        demangled = idc.demangle_name(name, 0)
        if demangled:
            name = demangled
    return name

def gen_mc(ea, maturity):
    func = idaapi.get_func(ea)
    mbr = idaapi.mba_ranges_t(func)
    idaapi.mark_cfunc_dirty(func.start_ea)
    flag = idaapi.DECOMP_NO_WAIT
    hf = idaapi.hexrays_failure_t()
    mba = idaapi.gen_microcode(mbr, hf, None, flag, maturity)
    return mba

def get_cfg_pseudo(ea):
    name = get_name(ea)
    if not name.startswith("sub_"):
        demangled = idc.demangle_name(name, 0)
        if demangled:
            name = demangled
    func = idaapi.get_func(ea)
    if not func:
        return {
            "status": -11,
            "msg": f"Address {ea:x} is not in any function"
        }
    imm_assign_count = 0
    eamap = dict()
    edges = list()
    inst_count = 0
    loop_set = set()
    max_indegree = 0
    max_outdegree = 0
    fc = idaapi.FlowChart(func)
    block_count = fc.size
    exits = list()
    for block in fc:
        eamap[block.id] = f"{block.start_ea:x}"
        max_indegree = max(max_indegree, sum(1 for _ in block.preds()))
        outdegree = sum(1 for _ in block.succs())
        if outdegree == 0:
            exits.append(block.id)
        max_outdegree = max(max_outdegree, outdegree)
        for succ in block.succs():
            if succ.id < block.id:
                loop_set.add(succ.id)
            edges.append((block.id, succ.id))
        inst_ea = block.start_ea
        while inst_ea < block.end_ea:
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, inst_ea)
            op0, op1, op2 = [insn.ops[i] for i in range(3)]
            if op0.type == idc.o_reg and op1.type == idc.o_imm and op2.type == idc.o_void:
                imm_assign_count += 1
            inst_count += 1
            inst_ea = idc.next_head(inst_ea)
    if edges:
        dom_set = find_all_dominance_sets(edges, fc[0].id)
        max_dom_count = max(len(v) for v in dom_set.values())
    else:
        max_dom_count = 0
    jdata = {
        "status": 0,
        "data": {
            "name": name,
            "ea": hex(ea),
            "maturity": 100,
            "size": idc.get_func_attr(ea, idc.FUNCATTR_END) - ea,
            "imm_assign_count": imm_assign_count,
            "block_count": block_count,
            "inst_count": inst_count,
            "eamap": eamap,
            "edges": edges,
            "exits": exits,
            "loop_count": len(loop_set),
            "max_indegree": max_indegree,
            "max_outdegree": max_outdegree,
            "max_dom_count": max_dom_count,
        }
    }
    return jdata

def get_cfg_micro(ea, maturity):
    name = get_name(ea)
    if not name.startswith("sub_"):
        demangled = idc.demangle_name(name, 0)
        if demangled:
            name = demangled
    mba = gen_mc(ea, maturity)
    if mba is None:
        return {
            "status": -21,
            "msg": f"Decompile failed {ea:x} {maturity}"
        }
    imm_assign_count = 0
    eamap = dict()
    edges = list()
    inst_count = 0
    loop_set = set()
    max_indegree = 0
    max_outdegree = 0
    block_count = mba.qty - 2 # virtual nodes: 1st last
    exits = list()
    class minst_counter(idaapi.minsn_visitor_t):
        def visit_minsn(self):
            nonlocal inst_count, imm_assign_count
            insn = self.curins
            if insn.l.t == idaapi.mop_n and insn.d.t == idaapi.mop_r:
                imm_assign_count += 1
            inst_count += 1
            return 0
    for i in range(0, mba.qty):
        mblock = mba.get_mblock(i)
        eamap[mblock.serial] = f"{mblock.start:x}"
        if i in [0, mba.qty - 1]:
            continue
        max_indegree = max(max_indegree, sum(1 for _ in mblock.preds()))
        outdegree = sum(1 for _ in mblock.succs())
        max_outdegree = max(max_outdegree, outdegree)
        if outdegree == 1 and next(mblock.succs()).serial == mba.qty - 1:
            # jump to (virtual) exit node
            exits.append(mblock.serial)
        else:
            for succ in mblock.succs():
                if succ.serial < mblock.serial:
                    loop_set.add(succ.serial)
                edges.append([mblock.serial, succ.serial])
    mba.for_all_insns(minst_counter())
    if edges:
        dom_set = find_all_dominance_sets(edges, mba.get_mblock(1).serial)
        max_dom_count = max(len(v) for v in dom_set.values())
    else:
        max_dom_count = 0
    dispatch_lst = list()
    if maturity >= idaapi.MMAT_CALLS:
        try:
            from DeOllvm import find_all_dispatch_blks_for_mba
            dispatch_lst = find_all_dispatch_blks_for_mba(mba)
        except Exception as e:
            pass
    jdata = {
        "status": 0,
        "data": {
            "name": name,
            "ea": hex(ea),
            "maturity": maturity,
            "size": idc.get_func_attr(ea, idc.FUNCATTR_END) - ea,
            "imm_assign_count": imm_assign_count,
            "block_count": block_count,
            "inst_count": inst_count,
            "eamap": eamap,
            "edges": edges,
            "exits": exits,
            "loop_count": len(loop_set),
            "max_indegree": max_indegree,
            "max_outdegree": max_outdegree,
            "max_dom_count": max_dom_count,
            "dispatch_lst": dispatch_lst,
        }
    }
    return jdata

def get_cfg_inner(ea, maturity):
    func = idaapi.get_func(int(ea, 16))
    func_ea = func.start_ea
    if func is None:
        return {
            "status": -1,
            "msg": "Invalid address"
        }
    if maturity <= 0 or maturity > 100:
        return {
            "status": -1,
            "msg": "Invalid maturity"
        }
    if maturity == 100:
        return get_cfg_pseudo(func_ea)
    return get_cfg_micro(func_ea, maturity)

def get_ea_inner():
    ea = idaapi.get_screen_ea()
    func = idaapi.get_func(ea)
    func_ea = 0 if func is None else func.start_ea
    return {
        "status": 0,
        "data": f"{func_ea:x}"
    } 

@app.get("/cfg")
async def get_cfg(ea: str, maturity: int):
    return wrap_func(get_cfg_inner)(ea, maturity)

@app.get("/ea")
async def get_ea():
    return wrap_func(get_ea_inner)()

import logging
logging.getLogger("uvicorn.access").disabled = True

def run_server():
    print(f"cfgraph listen {LISTEN_IP}:{LISTEN_PORT}")
    uvicorn.run("cfgraph:app", host=LISTEN_IP, port=LISTEN_PORT, access_log=False)

class AboutHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        idaapi.info("CFGraph by lich4")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class OpenHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        idaapi.open_url(f"http://127.0.0.1:{LISTEN_PORT}/static/")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class EAListener(idaapi.UI_Hooks):
    def screen_ea_changed(self, ea, prev_ea):
        global cur_ea
        func = idaapi.get_func(ea)
        if func:
            set_global("cur_ea", func.start_ea)
        return 0
ea_listener = EAListener()

class CFGraph(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "CFGraph plugin for IDA"
    help = "CFGraph"
    wanted_name = "CFGraph"

    def init(self):
        if not get_global("init"):
            set_global("init", True)
            threading.Thread(target=run_server, daemon=True).start()
        ea_listener.hook()
        self.register_menu("Edit/CFGraph/", "cfgraph:open", "Open", OpenHandler())
        self.register_menu("Edit/CFGraph/", "cfgraph:about", "About", AboutHandler())
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        pass

    def term(self):
        ea_listener.unhook()

    def register_menu(self, menu_path, act_name, label, handler):
        idaapi.register_action(idaapi.action_desc_t(act_name, label, handler))
        idaapi.attach_action_to_menu(menu_path, act_name, idaapi.SETMENU_APP)

def PLUGIN_ENTRY():
    return CFGraph()

