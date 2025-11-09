mermaid.initialize({
    startOnLoad: false,
    theme: "default",
    maxEdges: 10000,
    flowchart: {
        curve: "basis"
    }
});

const { createApp, ref, computed, onMounted, onBeforeUnmount } = Vue;
const app = createApp({
    setup() {
        let last_ea = "0";
        let h = null;
        const loading = ref(false);
        const conf = ref({
            use_micro: false,
            use_name: false,
            use_horizon: false,
        })
        const cfg_def = {
            name: "",
            ea: 0,
            size: 0,
            imm_assign_count: 0,
            code: {
                block_count: 0,
                inst_count: 0,
                eamap: {},
                edges: [],
                loop_count: 0,
                max_indegree: 0,
                max_outdegree: 0,
                max_dom_count: 0,
            },
            micro: {
                m_block_count: 0,
                m_inst_count: 0,
                m_eamap: {},
                m_edges: [],
                m_loop_count: 0,
                m_max_indegree: 0,
                m_max_outdegree: 0,
                m_max_dom_count: 0,
            }
        };
        const cfg_data = ref(cfg_def);

        const current = computed(() => {
            return conf.value.use_micro ? cfg_data.value.micro : cfg_data.value.code;
        });

        const draw = async() => {
            if (!cfg_data.value.name) {
                return;
            }
            const jcode = conf.value.use_micro ? cfg_data.value.micro : cfg_data.value.code;
            const edges = jcode.edges;
            const eamap = jcode.eamap;
            const exits = jcode.exits;
            var key_range, entry_or_exits;
            if (conf.value.use_micro) {
                entry_or_exits = [1, ...exits];
                key_range = [1, jcode.block_count];
            } else {
                entry_or_exits = [0, ...exits];
                key_range = [0, jcode.block_count - 1];
            }
            var mmd = `%%{init: {"layout":"elk"}}%%\n`;
            if (conf.value.use_horizon) {
                mmd += "graph LR\n"
            } else {
                mmd += "graph TD\n";
            }
            mmd += "    classDef EOE fill:#0f0\n";
            if (conf.value.use_name) {
                for (var key = key_range[0]; key <= key_range[1]; key++) {
                    if (entry_or_exits.includes(key)) {
                        mmd += "    " + key + "[" + eamap[key] + "]:::EOE\n";
                    } else {
                        mmd += "    " + key + "[" + eamap[key] + "]\n";
                    }
                }
            } else {
                for (const key of entry_or_exits) {
                    mmd += "    " + key + "[" + key + "]:::EOE\n";
                }
            }
            edges.forEach(t => {
                mmd += "    " + t[0] + " --> " + t[1] + "\n";
            });
            const el = document.getElementsByClassName("mermaid")[0];
            el.removeAttribute("data-processed");
            el.textContent = mmd;
            try {
                await mermaid.run({
                    nodes: [el]
                });
                const svg = el.querySelector("svg");
                panzoom(svg);
            } catch (e) {
                console.error("Mermaid rendering failed:", e);
            }
            loading.value = false;
        }

        const requestCFG = () => {
            $.ajax({
                url: "/cfg?ea=" + last_ea,
                method: "GET",
                success: async(jdata) => {
                    if (jdata.ea) {
                        cfg_data.value = jdata;
                        last_ea = jdata.ea;
                        loading.value = true;
                        await draw();
                    } else if (jdata.status != 0) {
                        cfg_data.value = cfg_def;
                    }
                },
                error: (xhr, status, error) => {
                    cfg_data.value = cfg_def;
                }
            });
        }

        onMounted(() => {
            h = setInterval(requestCFG, 1000);
            requestCFG();
        });

        onBeforeUnmount(() => {
            clearInterval(h);
        });
        return {loading, conf, cfg_data, current, draw};
    }
})
app.use(ElementPlus);
app.mount("#app");

