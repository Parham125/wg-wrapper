// Wintun needs an elevated process to create the adapter and edit the routing table, so the exe carries
// a manifest asking for it up front instead of failing halfway through connect().
fn main(){
	let manifest=r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}" />
    </application>
  </compatibility>
</assembly>"#;
	let attrs=tauri_build::Attributes::new().windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(manifest));
	tauri_build::try_build(attrs).expect("tauri-build failed");
}
