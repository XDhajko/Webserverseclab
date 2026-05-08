import streamlit as st
import json
import os
import pandas as pd
from core.ssh_manager import copy_key_to_secure_store, is_ntfs_like_path, save_uploaded_key_to_secure_store, _find_vagrant_key

TARGETS_FILE = "config/targets.json"


def _default_https_port(platform: str) -> int:
    return 7080 if platform == "ols" else 443

def load_targets():
    if not os.path.exists(TARGETS_FILE):
        return []
    with open(TARGETS_FILE, "r") as f:
        return json.load(f)

def save_targets(targets):
    os.makedirs(os.path.dirname(TARGETS_FILE), exist_ok=True)
    with open(TARGETS_FILE, "w") as f:
        json.dump(targets, f, indent=2)

@st.dialog("Add / Edit Target")
def target_dialog(target=None, index=None):
    is_edit = target is not None
    st.write(f"{'Edit existing' if is_edit else 'Add new'} virtualization target.")
    
    name = st.text_input("Target name", value=target.get("name", "") if is_edit else "")
    ip = st.text_input("IP or hostname", value=target.get("ip", "") if is_edit else "")
    
    platforms = ["apache", "nginx", "ols", "unknown"]
    sel_idx = 0
    if is_edit and target.get("platform") in platforms:
        sel_idx = platforms.index(target.get("platform"))
    platform = st.selectbox("Target Platform", options=platforms, index=sel_idx)

    https_port = st.number_input(
        "HTTPS Port (for TLS scanners)",
        min_value=1,
        max_value=65535,
        value=int(target.get("https_port", _default_https_port(platform)) if is_edit else _default_https_port(platform)),
        help="Used by TLS scanners such as testssl.sh. OLS defaults to 7080 in this lab."
    )
    
    ssh_port = st.number_input("SSH Port", min_value=1, max_value=65535, value=int(target.get("ssh_port", 22) if is_edit else 22))
    ssh_user = st.text_input("SSH Username", value=target.get("ssh_username", target.get("user", "vagrant")) if is_edit else "vagrant")

    auth_options = ["key", "password", "key+passphrase"]
    default_auth = target.get("ssh_auth_type", "key") if is_edit else "key"
    if default_auth not in auth_options:
        default_auth = "key"
    ssh_auth_type = st.selectbox("Authentication type", auth_options, index=auth_options.index(default_auth))

    key_path_original = target.get("ssh_key_original_path", "") if is_edit else ""
    key_path_internal = target.get("ssh_key_internal_path", "") if is_edit else ""
    key_passphrase = target.get("ssh_key_passphrase", "") if is_edit else ""
    ssh_password_saved = target.get("ssh_password", "") if is_edit else ""

    key_path_input = ""
    if ssh_auth_type in ["key", "key+passphrase"]:
        uploaded_key = st.file_uploader(
            "SSH private key file",
            type=None,
            key=f"ssh_key_upload_{'edit' if is_edit else 'new'}_{index if index is not None else 'x'}",
            help="Pick private key file directly from your filesystem."
        )

        if uploaded_key is not None:
            if st.button("Use uploaded key", width="stretch"):
                try:
                    copied = save_uploaded_key_to_secure_store(
                        uploaded_key.name,
                        uploaded_key.getvalue(),
                        name or "target",
                    )
                    st.session_state["_copied_key_path"] = str(copied)
                    st.session_state["_key_original_ref"] = f"uploaded:{uploaded_key.name}"
                    st.success(f"Uploaded key copied to secure store: {copied}")
                except Exception as exc:
                    st.error(f"Failed to use uploaded key: {exc}")

        st.caption("Optional fallback: paste key path manually")
        key_path_input = st.text_input("SSH private key path", value=key_path_original)
        if key_path_input and os.path.exists(os.path.expanduser(key_path_input)):
            if st.button("Copy key into secure key store", width="stretch"):
                try:
                    copied = copy_key_to_secure_store(key_path_input, name or "target")
                    st.session_state["_copied_key_path"] = str(copied)
                    st.session_state["_key_original_ref"] = key_path_input
                    st.success(f"Key copied to secure store: {copied}")
                except Exception as exc:
                    st.error(f"Failed to copy key: {exc}")

            if is_ntfs_like_path(key_path_input):
                st.warning(
                    "Selected key path appears to be on NTFS. SSH may reject it due to permissions. "
                    "Use the copy button above and connect using the internal key path."
                )
        elif key_path_input:
            st.warning("The provided key path does not exist on the controller host.")

        internal_show = st.session_state.get("_copied_key_path", key_path_internal)
        if internal_show:
            st.info(f"Internal key path used for SSH: {internal_show}")

        # Offer one-click Vagrant key refresh for lab targets
        vagrant_key = _find_vagrant_key(name) if name else None
        if vagrant_key is not None:
            if st.button("🔑 Refresh Key from Vagrant", type="secondary", use_container_width=True,
                         help="Re-import the current Vagrant private key for this VM into the secure store."):
                try:
                    copied = copy_key_to_secure_store(str(vagrant_key), name)
                    st.session_state["_copied_key_path"] = str(copied)
                    st.session_state["_key_original_ref"] = f"vagrant:{name}"
                    st.success(f"Vagrant key refreshed: {copied}")
                except Exception as exc:
                    st.error(f"Failed to refresh Vagrant key: {exc}")

        if ssh_auth_type == "key+passphrase":
            key_passphrase = st.text_input(
                "Key passphrase",
                value=key_passphrase,
                type="password",
                help="You can leave this blank if the key is not encrypted."
            )
    else:
        save_password = st.checkbox("Store SSH password in config (local only)", value=bool(ssh_password_saved))
        run_password = st.text_input(
            "SSH password",
            value=ssh_password_saved if save_password else "",
            type="password"
        )
        if save_password:
            st.warning("Stored passwords are local-only and should be protected by file permissions.")
            ssh_password_saved = run_password
        else:
            ssh_password_saved = ""
    
    if st.button("Save Target", type="primary"):
        if not name or not ip:
            st.error("Target name and IP/hostname are required.")
        else:
            targets = load_targets()
            internal_path = st.session_state.get("_copied_key_path", key_path_internal)
            original_ref = st.session_state.get("_key_original_ref", key_path_original)
            new_target = {
                "name": name,
                "ip": ip,
                "platform": platform,
                "user": ssh_user,
                "https_port": int(https_port),
                "ssh_port": int(ssh_port),
                "ssh_username": ssh_user,
                "ssh_auth_type": ssh_auth_type,
                "ssh_key_original_path": original_ref if ssh_auth_type in ["key", "key+passphrase"] else "",
                "ssh_key_internal_path": internal_path,
                "ssh_key_passphrase": key_passphrase if ssh_auth_type == "key+passphrase" else "",
                "ssh_password": ssh_password_saved if ssh_auth_type == "password" else "",
            }

            if ssh_auth_type in ["key", "key+passphrase"]:
                key_input = st.session_state.get("_copied_key_path", "")
                if not (internal_path or key_input):
                    st.error("Key authentication selected. Copy a private key into secure store first.")
                    return

            if is_edit:
                targets[index] = new_target
            else:
                targets.append(new_target)
            save_targets(targets)
            try:
                os.chmod(TARGETS_FILE, 0o600)
            except OSError:
                pass
            st.session_state["targets_updated"] = True
            if "_copied_key_path" in st.session_state:
                del st.session_state["_copied_key_path"]
            if "_key_original_ref" in st.session_state:
                del st.session_state["_key_original_ref"]
            st.rerun()

def render():
    st.title("Target Management")
    st.markdown("Add, edit, or remove virtualization infrastructure targets.")
    st.write("")
    
    if "targets_updated" in st.session_state:
        st.success("Target environment schema updated successfully.")
        del st.session_state["targets_updated"]
        
    targets = load_targets()
    
    # Render table of current targets
    if not targets:
        st.info("No targets configured. Add one below.")
        if st.button("Add New Target", use_container_width=True, icon=":material/add:"):
            target_dialog()
    else:
        df = pd.DataFrame(targets)
        safe_cols = ["name", "ip", "platform", "https_port", "ssh_port", "ssh_username", "ssh_auth_type"]
        df = df[[c for c in safe_cols if c in df.columns]]
        
        event = st.dataframe(
            df, 
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            width="stretch"
        )
        
        selected_indices = event.selection.rows
        
        st.write("")
        st.subheader("Manage Targets")
        
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            if st.button("Add New Target", icon=":material/add:", width="stretch"):
                target_dialog()
                
        with col2:
            if selected_indices:
                edit_sel = selected_indices[0]
                if st.button("Edit Selected", icon=":material/edit:", width="stretch"):
                    target_dialog(targets[edit_sel], edit_sel)
            else:
                st.button("Edit Selected", disabled=True, icon=":material/edit:", width="stretch")
                
        with col3:
            if selected_indices:
                del_sel = selected_indices[0]
                if st.button("Delete Selected", type="primary", icon=":material/delete:", width="stretch"):
                    targets.pop(del_sel)
                    save_targets(targets)
                    st.session_state["targets_updated"] = True
                    st.rerun()
            else:
                st.button("Delete Selected", type="primary", disabled=True, icon=":material/delete:", width="stretch")
