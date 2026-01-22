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
            maturity: "100",
            use_name: false,
        })
        const matlst = [
            {
                label: "LOCOPT",
                value: "3"
            },
            {
                label: "CALLS",
                value: "4"
            },
            {
                label: "GLBOPT1",
                value: "5"
            },
            {
                label: "GLBOPT2",
                value: "6"
            },
            {
                label: "GLBOPT3",
                value: "7"
            },
            {
                label: "LVARS",
                value: "8"
            },
            {
                label: "PSEUDO",
                value: "100"
            },
        ];
        const cfg_def = {
            name: "",
            ea: 0,
            size: 0,
            imm_assign_count: 0,
            block_count: 0,
            inst_count: 0,
            eamap: {},
            edges: [],
            loop_count: 0,
            max_indegree: 0,
            max_outdegree: 0,
            max_dom_count: 0,
        };
        const cfg_data = ref(cfg_def);

        const draw = async() => {
            if (!cfg_data.value.name) {
                return;
            }
            const edges = cfg_data.value.edges;
            const eamap = cfg_data.value.eamap;
            const exits = cfg_data.value.exits;
            const dispatch_lst = cfg_data.value.dispatch_lst || [];
            var key_range, entry_or_exits;
            if (cfg_data.value.maturity == 100) {
                entry_or_exits = [0, ...exits];
                key_range = [0, cfg_data.value.block_count - 1];
            } else {
                entry_or_exits = [1, ...exits];
                key_range = [1, cfg_data.value.block_count];
            }
            var mmd = `%%{init: {"layout":"elk"}}%%\n`;
            mmd += "graph TD\n";
            mmd += "    classDef ENDPT fill:#00FF00\n";
            mmd += "    classDef DISPATCH fill:#BC1717\n";
            for (const key of entry_or_exits) {
                mmd += "    " + key + ":::ENDPT\n";
            }
            for (const key of dispatch_lst) {
                mmd += "    " + key + ":::DISPATCH\n";
            }
            if (conf.value.use_name) {
                for (var key = key_range[0]; key <= key_range[1]; key++) {
                    mmd += "    " + key + "[" + eamap[key] + "]\n";
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
            if (last_ea == "0") {
                return;
            }
            let maturity = conf.value.maturity;
            $.ajax({
                url: `/cfg?ea=${last_ea}&maturity=${maturity}`,
                method: "GET",
                success: async(jdata) => {
                    if (jdata.status == 0) {
                        cfg_data.value = jdata.data;
                        loading.value = true;
                        await draw();
                    } else {
                        console.log(jdata.msg);
                        cfg_data.value = cfg_def;
                    }
                },
                error: (xhr, status, error) => {
                    cfg_data.value = cfg_def;
                }
            });
        }

        const requestCFGOnChange = () => {
            $.ajax({
                url: "/ea", 
                method: "GET",
                success: async(jdata) => {
                    let new_ea = jdata.data
                    if (new_ea != last_ea) {
                        last_ea = new_ea;
                        requestCFG();
                    }
                },
                error: (xhr, status, error) => {
                    cfg_data.value = cfg_def;
                }
            });
        }

        onMounted(() => {
            h = setInterval(requestCFGOnChange, 1000);
        });

        onBeforeUnmount(() => {
            clearInterval(h);
        });
        return {loading, conf, matlst, cfg_data, requestCFG};
    }
})

app.use(ElementPlus);
app.mount("#app");

