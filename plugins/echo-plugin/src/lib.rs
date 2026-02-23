mod logic;

wit_bindgen::generate!({
    world: "plugin",
    path: "../../wit",
});

struct SteelPlugin;

impl exports::steel::plugin::entry::Guest for SteelPlugin {
    fn invoke(
        call: exports::steel::plugin::entry::Call,
    ) -> exports::steel::plugin::entry::InvokeResult {
        let payload = logic::handle_invoke(&call.facet_id, call.method_id, &call.payload);
        exports::steel::plugin::entry::InvokeResult { payload }
    }
}

export!(SteelPlugin);
