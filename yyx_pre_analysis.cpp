
#include "dr_api.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drwrap.h"
#include <string>
#include <set>
#include <map>
#include <stack>
#include <fstream>

//std::set<std::string> modules;
std::set<std::string> symbols;
std::set<std::string> moff;

std::set<std::string> should_ignore_modules = { "drsyscall.dll", "drmgr.dll", "drreg.dll", "drsyms.dll", "drutil.dll", "drwrap.dll", "drx.dll", "dynamorio.dll" };

class symbolid {
public:
    std::string mname;
    size_t offset;
    std::string funcname;
    symbolid(std::string mname, size_t offset, std::string funcname) {
        this->mname = mname;
        this->offset = offset;
        this->funcname = funcname;
    }
    ~symbolid() {}
};

std::map<std::string, symbolid> mss;//遍历所有模块中的所有符号，信息记录在这里
std::stack<std::pair<symbolid, app_pc>> funcstack;//first is symbol, second is instr addr after call
std::string mainexe;
std::string mainfunc = "main";

static void
event_exit(void)
{
    drwrap_exit();
    drsym_exit();
    drmgr_exit();
}

void func(app_pc pc) {
    void* drcontext = dr_get_current_drcontext();
    instr_t instr;
    instr_init(drcontext, &instr);
    decode(drcontext, pc, &instr);
    dr_mcontext_t mcontext = { sizeof(mcontext),DR_MC_ALL };
    dr_get_mcontext(drcontext, &mcontext);
    app_pc target_pc = 0;
    module_data_t* mod;

    //mod = dr_lookup_module(pc);
    //const char* mname = dr_module_preferred_name(mod);
    //std::string mnamestr = mname;
    //std::string findstr = mnamestr + std::to_string(pc - mod->start);
    //auto it = mss.find(findstr);
    //if (moff.find(findstr) == moff.end() && it != mss.end()) {
    //    std::fstream f("D:/AProjects/BinaryCodeAnalysis/test/ignore_funcs.txt", std::ios::app);
    //    f << it->second.mname << "," << it->second.offset << "," << it->second.funcname << ";\n";
    //    //dr_printf("mname: %s, offset: %lld, func name: %s\n", it->second.mname.c_str(), it->second.offset, it->second.funcname.c_str());
    //    moff.insert(findstr);
    //    f.close();
    //}

    if (instr_is_call_direct(&instr)) {
        target_pc = instr_get_branch_target_pc(&instr);
        mod = dr_lookup_module(target_pc);
    }
    else if(instr_is_call_indirect(&instr)){
        target_pc = opnd_compute_address(instr_get_src(&instr, 0), &mcontext);
        mod = dr_lookup_module(target_pc);
    }

    

    module_data_t* mod2 = dr_lookup_module(pc);
    const char* mname2 = dr_module_preferred_name(mod2);
    //dr_printf("mname2: %s, pc: %x\n", mname2, pc);
    if (!strcmp(mname2, "main.exe") && (pc - mod2->start) == 0x263b) {
        dr_printf("log63\n");
        const char* mname = dr_module_preferred_name(mod);
        dr_printf("mname: %s, target_offset: %x\n", mname, target_pc - mod2->start);
        char buf[1024];
        disassemble_to_buffer(drcontext, target_pc, target_pc, true, true, buf, 1024, NULL);
        dr_printf("mname: %s, buf: %s\n", mname, buf);
        dr_printf("is call direct: %d\n", (int)instr_is_call_direct(&instr));
        app_pc tmp_pc;
        instr_t target_instr;
        instr_init(drcontext, &target_instr);
        decode(drcontext, mod2->start+0x4108, &target_instr);
        instr_get_rel_data_or_instr_target(&target_instr, &tmp_pc);
        app_pc addr = (app_pc)opnd_get_addr(instr_get_src(&instr, 0));
        dr_printf("tmp pc: %x, addr: %x\n", tmp_pc, addr);
    }

    if (/*!strcmp(mname2, "main.exe") && */(pc - mod2->start) == 0x4108) {
        //dr_printf("log70\n");
        /*char buf[1024];
        disassemble_to_buffer(drcontext, pc, pc, true, true, buf, 1024, NULL);
        dr_printf("mname: %s, buf: %s\n", mname2, buf);*/
        //dr_printf("mname: %s, target_offset: %x\n", dr_module_preferred_name(mod), target_pc - mod2->start);
    }

    if (instr_is_call(&instr)) {
        const char* mname = dr_module_preferred_name(mod);
        if (mname != NULL && target_pc != 0) {
            std::string tmp(mname);
            std::string tmp2 = tmp + std::to_string(target_pc - mod->start);
            auto it = mss.find(tmp2);
            if (moff.find(tmp2) == moff.end() && it != mss.end()) {
                std::fstream f("D:/AProjects/BinaryCodeAnalysis/test/ignore_funcs.txt", std::ios::app);
                f << it->second.mname << "," << it->second.offset << "," << it->second.funcname << ";\n";
                //dr_printf("mname: %s, offset: %lld, func name: %s\n", it->second.mname.c_str(), it->second.offset, it->second.funcname.c_str());
                moff.insert(tmp2);
                f.close();
            }
            if (it == mss.end()) {
                std::fstream f("D:/AProjects/BinaryCodeAnalysis/test/notfound.txt", std::ios::app);
                f << "mname: " << tmp << ", offset: " << std::hex << target_pc - mod->start << "\n";
                f.close();
                //dr_printf("cannot find! mname: %s, offset: %x\n", tmp.c_str(), target_pc - mod->start);
            }
            if ((target_pc - mod->start) == 0x3bb0) {
                dr_printf("log77\n");
            }
        }
        else if (mname == NULL) {
            module_data_t* mod2 = dr_lookup_module(pc);
            const char* mname2 = dr_module_preferred_name(mod2);
            dr_printf("mname2: %s, pc: %x\n", mname2, pc);
            /*if (!strcmp(mname2, "main.exe") && (pc - mod2->start) == 0x263b) {
                dr_printf("log85\n");
            }*/
            /*std::fstream f("D:/AProjects/BinaryCodeAnalysis/test/mnamenull.txt", std::ios::app);
            f << std::hex << pc << "\n";
            f.close();*/
        }
        else if (target_pc == 0) {
            dr_printf("target_pc == 0! mname: %s, pc: %x\n", mname, pc);
        }
    }
}

static bool
sym_callback(const char* name, size_t modoffs, void* data) {
    std::string mnamestr((const char*)data);
    if (should_ignore_modules.find(mnamestr) == should_ignore_modules.end()) {
        std::string symbol = mnamestr + std::to_string(modoffs);
        if (symbols.find(symbol) == symbols.end()) {
            symbols.insert(symbol);
            std::string funcnamestr(name);
            symbolid si(mnamestr, modoffs, funcnamestr);
            mss.insert(std::make_pair(symbol, si));
            std::fstream f("D:/AProjects/BinaryCodeAnalysis/test/symbol.txt", std::ios::app);
            f << "mname: " << mnamestr << ", funcname: " << funcnamestr << ", offset: " << std::hex << modoffs << "\n";
            f.close();
        }
    }
    return true;
}

//void func2(app_pc pc) {
//    void* drcontext = dr_get_current_drcontext();
//    //instr_t instr;
//    //instr_init(drcontext, &instr);
//    //decode(drcontext, pc, &instr);
//    //dr_mcontext_t mcontext = { sizeof(mcontext),DR_MC_ALL };
//    //dr_get_mcontext(drcontext, &mcontext);
//    module_data_t* mod = dr_lookup_module(pc);
//    const char* mname = dr_module_preferred_name(mod);
//    std::string mnamestr = mname;
//    uint64 offset = pc - mod->start;
//
//}

void callfunc(app_pc instr_addr, app_pc target_addr) {
    void* drcontext = dr_get_current_drcontext();
    instr_t instr;
    instr_init(drcontext, &instr);
    decode(drcontext, instr_addr, &instr);
    module_data_t* curmod = dr_lookup_module(instr_addr);
    const char* curmname = dr_module_preferred_name(curmod);
    std::string curmnamestr = curmname;
    uint64 instr_offset = instr_addr - curmod->start;
    module_data_t* mod = dr_lookup_module(target_addr);
    const char* mname = dr_module_preferred_name(mod);
    uint64 target_offset = target_addr - mod->start;
    std::string funcnamestr;
    if (mname != NULL && target_addr != 0 && should_ignore_modules.find(std::string(mname)) == should_ignore_modules.end()) {
        std::fstream ignore_funcs("D:/AProjects/BinaryCodeAnalysis/test/ignore_funcs.txt", std::ios::app);
        std::fstream ignore_funcs_plus("D:/AProjects/BinaryCodeAnalysis/test/ignore_funcs_plus.txt", std::ios::app);
        std::string mnamestr(mname);
        std::string symbol = mnamestr + std::to_string(target_offset);
        auto it = mss.find(symbol);
        bool mainexe2others = funcstack.empty()? false : (funcstack.top().first.mname == mainexe && mnamestr != mainexe);
        bool mainfunc2others = funcstack.empty() ? false : (funcstack.top().first.funcname == mainfunc && mnamestr != mainexe);
        if (it != mss.end()) {
            //if (moff.find(symbol) == moff.end())
            {
                ignore_funcs << it->second.mname << "," << std::hex << it->second.offset << "," << it->second.funcname << "," << mainexe2others << "," << mainfunc2others << ";\n";
                //dr_printf("mname: %s, offset: %lld, func name: %s\n", it->second.mname.c_str(), it->second.offset, it->second.funcname.c_str());
                moff.insert(symbol);
            }
            funcnamestr = it->second.funcname;
        }
        else {
            //if (moff.find(symbol) == moff.end())
            {
                ignore_funcs << mnamestr << "," << std::hex << target_offset << ",symbolnotfound," << mainexe2others << "," << mainfunc2others << ";\n";
                std::fstream f("D:/AProjects/BinaryCodeAnalysis/test/notfound.txt", std::ios::app);
                f << "instr mname: " << curmnamestr << ", instr offset: " << std::hex << instr_offset << ", target mname: " << mnamestr << ", target offset: " << std::hex << target_offset << "\n";
                f.close();
                moff.insert(symbol);
                //dr_printf("cannot find! mname: %s, offset: %x\n", tmp.c_str(), target_pc - mod->start);
            }
            funcnamestr = "symbolnotfound";
        }
        ignore_funcs_plus << "instr mname: " << curmnamestr << ", instr offset: " << std::hex << instr_offset << ", target mname: " << mnamestr << ", target offset: " << std::hex << target_offset << "\n";
        ignore_funcs.close();
        ignore_funcs_plus.close();
        symbolid si(mnamestr, target_offset, funcnamestr);
        funcstack.push(std::make_pair(si, instr_addr + instr_length(drcontext, &instr)));
    }
    else if (mname == NULL) {
        dr_printf("instr mname: %s, instr_addr: %x\n", curmname, instr_addr);
        /*if (!strcmp(mname2, "main.exe") && (pc - mod2->start) == 0x263b) {
            dr_printf("log85\n");
        }*/
        /*std::fstream f("D:/AProjects/BinaryCodeAnalysis/test/mnamenull.txt", std::ios::app);
        f << std::hex << pc << "\n";
        f.close();*/
    }
    else if (target_addr == 0) {
        dr_printf("target_addr == 0! instr mname: %s, instr_addr: %x\n", curmname, instr_addr);
    }
}

static void
at_call(app_pc instr_addr, app_pc target_addr)
{
    callfunc(instr_addr, target_addr);
}

static void
at_call_ind(app_pc instr_addr, app_pc target_addr)
{
    //void* drcontext = dr_get_current_drcontext();
    //module_data_t* mod = dr_lookup_module(instr_addr);
    //const char* mname = dr_module_preferred_name(mod);
    ////dr_printf("mname2: %s, pc: %x\n", mname2, pc);
    //if (!strcmp(mname, "main.exe") && (instr_addr - mod->start) == 0x263b) {
    //    dr_printf("at call ind, target: %x\n", target_addr);
    //}
    callfunc(instr_addr, target_addr);
}

static void
at_return(app_pc instr_addr, app_pc target_addr)
{
    if (funcstack.empty()) {
        dr_printf("WARNING! funcstack is empty!\n");
    }
    else {
        std::stack<std::pair<symbolid, app_pc>> puthere;
        app_pc addr_after_call = funcstack.top().second;
        while (addr_after_call != target_addr) {
            puthere.push(funcstack.top());
            funcstack.pop();
            if (funcstack.empty()) {
                dr_printf("WARNING! maybe jmp to func with ret!\n");
            }
            addr_after_call = funcstack.top().second;
        }
        if (addr_after_call == target_addr) {
            funcstack.pop();
        }
        else {
            while (!puthere.empty()) {
                funcstack.push(puthere.top());
                puthere.pop();
            }
        }
    }
}

dr_emit_flags_t
app_instruction_val(void* drcontext, void* tag, instrlist_t* bb, instr_t* instr,
    bool for_trace, bool translating, void* user_data) {

    if (instr_is_call_direct(instr)) {
        dr_insert_call_instrumentation(drcontext, bb, instr, (app_pc)at_call);
    }
    else if (instr_is_call_indirect(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_call_ind,
            SPILL_SLOT_1);
    }
    else if (instr_is_return(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_return,
            SPILL_SLOT_1);
    }

    /*app_pc pc = instr_get_app_pc(instr);
    opnd_t opnd_curpc = opnd_create_immed_int64((long long)pc, OPSZ_8);
    dr_insert_clean_call(drcontext, bb, instr, func, false, 1, opnd_curpc);*/

    //dr_insert_clean_call(drcontext, bb, instr, func, false, 1, opnd_curpc);

    return DR_EMIT_DEFAULT;
}

//void
//module_load_event(void* drcontext, const module_data_t* mod, bool loaded)
//{
//    module_data_t* exe = dr_get_main_module();
//    std::string mainexe = std::string(dr_module_preferred_name(exe));
//}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char* argv[])
{
    dr_set_client_name("client_get_executed_func", "3538635827@qq.com");
    
    drmgr_init();
    drwrap_init();
    drsym_init(0);

    std::fstream f1("D:/AProjects/BinaryCodeAnalysis/test/symbol.txt", std::ios::out);
    f1.close();
    std::fstream f2("D:/AProjects/BinaryCodeAnalysis/test/ignore_funcs.txt", std::ios::out);
    f2.close();
    std::fstream f3("D:/AProjects/BinaryCodeAnalysis/test/notfound.txt", std::ios::out);
    f3.close();
    std::fstream f4("D:/AProjects/BinaryCodeAnalysis/test/mnamenull.txt", std::ios::out);
    f4.close();
    std::fstream f5("D:/AProjects/BinaryCodeAnalysis/test/ignore_funcs_plus.txt", std::ios::out);
    f5.close();

    dr_module_iterator_t* iter = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(iter)) {
        module_data_t* mod = dr_module_iterator_next(iter);
        /*const char* tmp = "MSVCP140.dll";
        if (!strcmp(dr_module_preferred_name(mod), tmp)) {
            dr_printf("MSVCP140.DLL path: %s\n", mod->full_path);
        }*/
        if (mod != NULL) {
            const char* mname = dr_module_preferred_name(mod);
            //modules.insert(mname);
            drsym_enumerate_symbols(mod->full_path, sym_callback, (void*)mname, DRSYM_DEFAULT_FLAGS);
            dr_free_module_data(mod);
        }
    }
    dr_module_iterator_stop(iter);

    module_data_t* exe = dr_get_main_module();
    mainexe = std::string(dr_module_preferred_name(exe));
    dr_printf("mainexe: %s\n", mainexe.c_str());

    //if (!drmgr_register_module_load_event(module_load_event)) DR_ASSERT_MSG(false, "drmgr_register_module_load_event false");
    if (!drmgr_register_bb_instrumentation_event(NULL, app_instruction_val, NULL)) DR_ASSERT_MSG(false, "drmgr_register_bb_instrumentation_event false");

    dr_register_exit_event(event_exit);
}

