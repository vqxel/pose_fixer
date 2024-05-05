extern crate proc_macro;

use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;

use crate::ctxt::Ctxt;
use crate::security_mode::SecurityMode;

mod ctxt;
mod security_mode;
mod uuid;

use crate::uuid::Uuid;

#[derive(Debug, FromMeta)]
struct ServiceArgs {
    uuid: Uuid,
}

#[derive(Debug, FromMeta)]
struct DescriptorArgs {
    uuid: Uuid,
    #[darling(default)]
    security: Option<SecurityMode>,
    #[darling(default)]
    value: Option<syn::Expr>,
}

#[derive(Debug, FromMeta)]
struct CharacteristicArgs {
    uuid: Uuid,
    #[darling(default)]
    read: bool,
    #[darling(default)]
    write: bool,
    #[darling(default)]
    write_without_response: bool,
    #[darling(default)]
    notify: bool,
    #[darling(default)]
    indicate: bool,
    #[darling(default)]
    security: Option<SecurityMode>,
    #[darling(default)]
    value: Option<syn::Expr>,
    #[darling(default, multiple)]
    descriptor: Vec<DescriptorArgs>,
}

#[derive(Debug)]
struct Characteristic {
    name: String,
    ty: syn::Type,
    args: CharacteristicArgs,
    span: Span,
    vis: syn::Visibility,
}

#[proc_macro_attribute]
pub fn gatt_server(_args: TokenStream, item: TokenStream) -> TokenStream {
    // Context for error reporting
    let ctxt = Ctxt::new();

    let mut struc = syn::parse_macro_input!(item as syn::ItemStruct);

    let struct_vis = &struc.vis;
    let struct_fields = match &mut struc.fields {
        syn::Fields::Named(n) => n,
        _ => {
            let s = struc.ident;

            ctxt.error_spanned_by(s, "gatt_server structs must have named fields, not tuples.");

            return TokenStream::new();
        }
    };
    let fields = struct_fields.named.iter().cloned().collect::<Vec<syn::Field>>();

    let struct_name = struc.ident.clone();
    let event_enum_name = format_ident!("{}Event", struct_name);

    let mut code_register_init = TokenStream2::new();
    let mut code_on_write = TokenStream2::new();
    let mut code_event_enum = TokenStream2::new();

    let ble = quote!(::nrf_softdevice::ble);

    for field in fields.iter() {
        let name = field.ident.as_ref().unwrap();
        let ty = &field.ty;
        let span = field.ty.span();
        code_register_init.extend(quote_spanned!(span=>
            #name: #ty::new(sd)?,
        ));

        if let syn::Type::Path(p) = &field.ty {
            let name_pascal = format_ident!("{}", inflector::cases::pascalcase::to_pascal_case(&name.to_string()));
            let event_enum_ty = p.path.get_ident().unwrap();
            let event_enum_variant = format_ident!("{}Event", event_enum_ty);
            code_event_enum.extend(quote_spanned!(span=>
                #name_pascal(#event_enum_variant),
            ));

            code_on_write.extend(quote_spanned!(span=>
                if let Some(e) = self.#name.on_write(handle, data) {
                    return Some(#event_enum_name::#name_pascal(e));
                }
            ));
        }
    }

    struct_fields.named = syn::punctuated::Punctuated::from_iter(fields);
    let struc_vis = struc.vis.clone();

    let result = quote! {
        #struc

        impl #struct_name {
            #struct_vis fn new(sd: &mut ::nrf_softdevice::Softdevice) -> Result<Self, #ble::gatt_server::RegisterError>
            {
                Ok(Self {
                    #code_register_init
                })
            }
        }

        #struc_vis enum #event_enum_name {
            #code_event_enum
        }

        impl #ble::gatt_server::Server for #struct_name {
            type Event = #event_enum_name;

            fn on_write(&self, _conn: &::nrf_softdevice::ble::Connection, handle: u16, op: ::nrf_softdevice::ble::gatt_server::WriteOp, offset: usize, data: &[u8]) -> Option<Self::Event> {
                use #ble::gatt_server::Service;

                #code_on_write
                None
            }
        }
    };

    match ctxt.check() {
        Ok(()) => result.into(),
        Err(e) => e.into(),
    }
}

#[proc_macro_attribute]
pub fn gatt_service(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(args as syn::AttributeArgs);
    let mut struc = syn::parse_macro_input!(item as syn::ItemStruct);

    let ctxt = Ctxt::new();

    let args = match ServiceArgs::from_list(&args) {
        Ok(v) => v,
        Err(e) => {
            ctxt.error_spanned_by(e.write_errors(), "ServiceArgs Parsing failed");
            return ctxt.check().unwrap_err().into();
        }
    };

    let mut chars = Vec::new();

    let struct_vis = &struc.vis;
    let struct_fields = match &mut struc.fields {
        syn::Fields::Named(n) => n,
        _ => {
            let s = struc.ident;

            ctxt.error_spanned_by(s, "gatt_service structs must have named fields, not tuples.");

            return ctxt.check().unwrap_err().into();
        }
    };
    let mut fields = struct_fields.named.iter().cloned().collect::<Vec<syn::Field>>();
    let mut err: Option<Error> = None;
    fields.retain(|field| {
        if let Some(attr) = field
            .attrs
            .iter()
            .find(|attr| attr.path.segments.len() == 1 && attr.path.segments.first().unwrap().ident == "characteristic")
        {
            let args = attr.parse_meta().unwrap();

            let args = match CharacteristicArgs::from_meta(&args) {
                Ok(v) => v,
                Err(e) => {
                    err = Some(e);
                    return false;
                }
            };

            chars.push(Characteristic {
                name: field.ident.as_ref().unwrap().to_string(),
                ty: field.ty.clone(),
                args,
                span: field.ty.span(),
                vis: field.vis.clone(),
            });

            false
        } else {
            true
        }
    });

    if let Some(err) = err {
        let desc = err.to_string();
        ctxt.error_spanned_by(
            err.write_errors(),
            format!("Parsing characteristics was unsuccessful: {}", desc),
        );
        return ctxt.check().unwrap_err().into();
    }

    //panic!("chars {:?}", chars);
    let struct_name = struc.ident.clone();
    let event_enum_name = format_ident!("{}Event", struct_name);

    let mut code_impl = TokenStream2::new();
    let mut code_build_chars = TokenStream2::new();
    let mut code_struct_init = TokenStream2::new();
    let mut code_on_write = TokenStream2::new();
    let mut code_event_enum = TokenStream2::new();

    let ble = quote!(::nrf_softdevice::ble);

    for ch in &chars {
        let name_pascal = inflector::cases::pascalcase::to_pascal_case(&ch.name);
        let char_name = format_ident!("{}", ch.name);
        let value_handle = format_ident!("{}_value_handle", ch.name);
        let cccd_handle = format_ident!("{}_cccd_handle", ch.name);
        let get_fn = format_ident!("{}_get", ch.name);
        let set_fn = format_ident!("{}_set", ch.name);
        let notify_fn = format_ident!("{}_notify", ch.name);
        let indicate_fn = format_ident!("{}_indicate", ch.name);
        let fn_vis = ch.vis.clone();

        let uuid = ch.args.uuid;
        let read = ch.args.read;
        let write = ch.args.write;
        let write_without_response = ch.args.write_without_response;
        let notify = ch.args.notify;
        let indicate = ch.args.indicate;
        let ty = &ch.ty;
        let ty_as_val = quote!(<#ty as #ble::GattValue>);
        let value = match &ch.args.value {
            Some(v) => quote! { #v },
            None => quote! { [123u8; #ty_as_val::MIN_SIZE] },
        };

        let descriptors: Vec<TokenStream2> = ch
            .args
            .descriptor
            .iter()
            .map(|descriptor_args| {
                let descriptor_uuid = descriptor_args.uuid;
                let security = descriptor_args.security.as_ref().unwrap();
                let value = descriptor_args.value.as_ref().unwrap();

                quote! {
                    let _ = cb
                        .add_descriptor(
                            #descriptor_uuid,
                            #ble::gatt_server::characteristic::Attribute::new(#value)
                            .security(#security)
                            .variable_len(#value.len() as u16)
                        )?;
                }
            })
            .collect();

        let security = if let Some(security) = ch.args.security {
            let security_inner = security.to_token_stream();
            quote!(attr = attr.read_security(#security_inner).write_security(#security_inner))
        } else {
            quote!()
        };

        fields.push(syn::Field {
            ident: Some(value_handle.clone()),
            ty: syn::Type::Verbatim(quote!(u16)),
            attrs: Vec::new(),
            colon_token: Default::default(),
            vis: syn::Visibility::Inherited,
        });

        code_build_chars.extend(quote_spanned!(ch.span=>
            let #char_name = {
                let val = #value;
                let mut attr = #ble::gatt_server::characteristic::Attribute::new(&val);
                if #ty_as_val::MAX_SIZE != #ty_as_val::MIN_SIZE {
                    attr = attr.variable_len(#ty_as_val::MAX_SIZE as u16);
                }
                #security;
                let props = #ble::gatt_server::characteristic::Properties {
                    read: #read,
                    write: #write,
                    write_without_response: #write_without_response,
                    notify: #notify,
                    indicate: #indicate,
                    ..Default::default()
                };
                let metadata = #ble::gatt_server::characteristic::Metadata::new(props);
                let mut cb = service_builder.add_characteristic(#uuid, attr, metadata)?;

                #(#descriptors)*

                cb.build()
            };
        ));

        code_struct_init.extend(quote_spanned!(ch.span=>
            #value_handle: #char_name.value_handle,
        ));

        code_impl.extend(quote_spanned!(ch.span=>
            #fn_vis fn #get_fn(&self) -> Result<#ty, #ble::gatt_server::GetValueError> {
                let sd = unsafe { ::nrf_softdevice::Softdevice::steal() };
                let buf = &mut [0u8; #ty_as_val::MAX_SIZE];
                let size = #ble::gatt_server::get_value(sd, self.#value_handle, buf)?;
                Ok(#ty_as_val::from_gatt(&buf[..size]))
            }

            #fn_vis fn #set_fn(&self, val: &#ty) -> Result<(), #ble::gatt_server::SetValueError> {
                let sd = unsafe { ::nrf_softdevice::Softdevice::steal() };
                let buf = #ty_as_val::to_gatt(val);
                #ble::gatt_server::set_value(sd, self.#value_handle, buf)
            }
        ));

        if indicate || notify {
            fields.push(syn::Field {
                ident: Some(cccd_handle.clone()),
                ty: syn::Type::Verbatim(quote!(u16)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: syn::Visibility::Inherited,
            });
            code_struct_init.extend(quote_spanned!(ch.span=>
                #cccd_handle: #char_name.cccd_handle,
            ));
        }

        if write || write_without_response {
            let case_write = format_ident!("{}Write", name_pascal);
            code_event_enum.extend(quote_spanned!(ch.span=>
                #case_write(#ty),
            ));
            code_on_write.extend(quote_spanned!(ch.span=>
                if handle == self.#value_handle {
                    if data.len() < #ty_as_val::MIN_SIZE {
                        return self.#get_fn().ok().map(#event_enum_name::#case_write);
                    } else {
                        return Some(#event_enum_name::#case_write(#ty_as_val::from_gatt(data)));
                    }
                }
            ));
        }

        if notify {
            code_impl.extend(quote_spanned!(ch.span=>
                #fn_vis fn #notify_fn(
                    &self,
                    conn: &#ble::Connection,
                    val: &#ty,
                ) -> Result<(), #ble::gatt_server::NotifyValueError> {
                    let buf = #ty_as_val::to_gatt(val);
                    #ble::gatt_server::notify_value(conn, self.#value_handle, buf)
                }
            ));

            if !indicate {
                let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                code_event_enum.extend(quote_spanned!(ch.span=>
                    #case_cccd_write{notifications: bool},
                ));
                code_on_write.extend(quote_spanned!(ch.span=>
                    if handle == self.#cccd_handle && !data.is_empty() {
                        match data[0] & 0x01 {
                            0x00 => return Some(#event_enum_name::#case_cccd_write{notifications: false}),
                            0x01 => return Some(#event_enum_name::#case_cccd_write{notifications: true}),
                            _ => {},
                        }
                    }
                ));
            }
        }

        if indicate {
            code_impl.extend(quote_spanned!(ch.span=>
                #fn_vis fn #indicate_fn(
                    &self,
                    conn: &#ble::Connection,
                    val: &#ty,
                ) -> Result<(), #ble::gatt_server::IndicateValueError> {
                    let buf = #ty_as_val::to_gatt(val);
                    #ble::gatt_server::indicate_value(conn, self.#value_handle, buf)
                }
            ));

            if !notify {
                let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                code_event_enum.extend(quote_spanned!(ch.span=>
                    #case_cccd_write{indications: bool},
                ));
                code_on_write.extend(quote_spanned!(ch.span=>
                    if handle == self.#cccd_handle && !data.is_empty() {
                        match data[0] & 0x02 {
                            0x00 => return Some(#event_enum_name::#case_cccd_write{indications: false}),
                            0x02 => return Some(#event_enum_name::#case_cccd_write{indications: true}),
                            _ => {},
                        }
                    }
                ));
            }
        }

        if indicate && notify {
            let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

            code_event_enum.extend(quote_spanned!(ch.span=>
                #case_cccd_write{indications: bool, notifications: bool},
            ));
            code_on_write.extend(quote_spanned!(ch.span=>
                if handle == self.#cccd_handle && !data.is_empty() {
                    match data[0] & 0x03 {
                        0x00 => return Some(#event_enum_name::#case_cccd_write{indications: false, notifications: false}),
                        0x01 => return Some(#event_enum_name::#case_cccd_write{indications: false, notifications: true}),
                        0x02 => return Some(#event_enum_name::#case_cccd_write{indications: true, notifications: false}),
                        0x03 => return Some(#event_enum_name::#case_cccd_write{indications: true, notifications: true}),
                        _ => {},
                    }
                }
            ));
        }
    }

    let uuid = args.uuid;
    struct_fields.named = syn::punctuated::Punctuated::from_iter(fields);
    let struc_vis = struc.vis.clone();

    let result = quote! {
        #struc

        #[allow(unused)]
        impl #struct_name {
            #struct_vis fn new(sd: &mut ::nrf_softdevice::Softdevice) -> Result<Self, #ble::gatt_server::RegisterError>
            {
                let mut service_builder = #ble::gatt_server::builder::ServiceBuilder::new(sd, #uuid)?;

                #code_build_chars

                let _ = service_builder.build();

                Ok(Self {
                    #code_struct_init
                })
            }

            #code_impl
        }

        impl #ble::gatt_server::Service for #struct_name {
            type Event = #event_enum_name;

            fn on_write(&self, handle: u16, data: &[u8]) -> Option<Self::Event> {
                #code_on_write
                None
            }
        }

        #[allow(unused)]
        #struc_vis enum #event_enum_name {
            #code_event_enum
        }
    };
    match ctxt.check() {
        Ok(()) => result.into(),
        Err(e) => e.into(),
    }
}

#[proc_macro_attribute]
pub fn gatt_client(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(args as syn::AttributeArgs);
    let mut struc = syn::parse_macro_input!(item as syn::ItemStruct);

    let ctxt = Ctxt::new();

    let args = match ServiceArgs::from_list(&args) {
        Ok(v) => v,
        Err(e) => {
            return e.write_errors().into();
        }
    };

    let mut chars = Vec::new();

    let struct_fields = match &mut struc.fields {
        syn::Fields::Named(n) => n,
        _ => {
            let s = struc.ident;

            ctxt.error_spanned_by(s, "gatt_client structs must have named fields, not tuples.");

            return TokenStream::new();
        }
    };
    let mut fields = struct_fields.named.iter().cloned().collect::<Vec<syn::Field>>();
    let mut err = None;
    fields.retain(|field| {
        if let Some(attr) = field
            .attrs
            .iter()
            .find(|attr| attr.path.segments.len() == 1 && attr.path.segments.first().unwrap().ident == "characteristic")
        {
            let args = attr.parse_meta().unwrap();

            let args = match CharacteristicArgs::from_meta(&args) {
                Ok(v) => v,
                Err(e) => {
                    err = Some(e.write_errors().into());
                    return false;
                }
            };

            chars.push(Characteristic {
                name: field.ident.as_ref().unwrap().to_string(),
                ty: field.ty.clone(),
                args,
                span: field.ty.span(),
                vis: field.vis.clone(),
            });

            false
        } else {
            true
        }
    });

    if let Some(err) = err {
        return err;
    }

    //panic!("chars {:?}", chars);
    let struct_name = struc.ident.clone();
    let event_enum_name = format_ident!("{}Event", struct_name);

    let mut code_impl = TokenStream2::new();
    let mut code_disc_new = TokenStream2::new();
    let mut code_disc_char = TokenStream2::new();
    let mut code_disc_done = TokenStream2::new();
    let mut code_event_enum = TokenStream2::new();
    let mut code_on_hvx = TokenStream2::new();

    let ble = quote!(::nrf_softdevice::ble);

    fields.push(syn::Field {
        ident: Some(format_ident!("conn")),
        ty: syn::Type::Verbatim(quote!(#ble::Connection)),
        attrs: Vec::new(),
        colon_token: Default::default(),
        vis: syn::Visibility::Inherited,
    });

    for ch in &chars {
        let name_pascal = inflector::cases::pascalcase::to_pascal_case(&ch.name);
        let uuid_field = format_ident!("{}_uuid", ch.name);
        let value_handle = format_ident!("{}_value_handle", ch.name);
        let cccd_handle = format_ident!("{}_cccd_handle", ch.name);
        let read_fn = format_ident!("{}_read", ch.name);
        let write_fn = format_ident!("{}_write", ch.name);
        let write_wor_fn = format_ident!("{}_write_without_response", ch.name);
        let write_try_wor_fn = format_ident!("{}_try_write_without_response", ch.name);
        let cccd_write_fn = format_ident!("{}_cccd_write", ch.name);
        let fn_vis = ch.vis.clone();

        let uuid = ch.args.uuid;
        let read = ch.args.read;
        let write = ch.args.write;
        let notify = ch.args.notify;
        let indicate = ch.args.indicate;
        let ty = &ch.ty;
        let ty_as_val = quote!(<#ty as #ble::GattValue>);

        fields.push(syn::Field {
            ident: Some(value_handle.clone()),
            ty: syn::Type::Verbatim(quote!(u16)),
            attrs: Vec::new(),
            colon_token: Default::default(),
            vis: syn::Visibility::Inherited,
        });

        fields.push(syn::Field {
            ident: Some(uuid_field.clone()),
            ty: syn::Type::Verbatim(quote!(#ble::Uuid)),
            attrs: Vec::new(),
            colon_token: Default::default(),
            vis: syn::Visibility::Inherited,
        });

        code_disc_new.extend(quote_spanned!(ch.span=>
            #value_handle: 0,
            #uuid_field: #uuid,
        ));

        let mut code_descs = TokenStream2::new();
        if indicate || notify {
            code_descs.extend(quote_spanned!(ch.span=>
                if _desc_uuid == #ble::Uuid::new_16(::nrf_softdevice::raw::BLE_UUID_DESCRIPTOR_CLIENT_CHAR_CONFIG as u16) {
                    self.#cccd_handle = desc.handle;
                }
            ));
        }

        code_disc_char.extend(quote_spanned!(ch.span=>
            if let Some(char_uuid) = characteristic.uuid {
                if char_uuid == self.#uuid_field {
                    // TODO maybe check the char_props have the necessary operations allowed? read/write/notify/etc
                    self.#value_handle = characteristic.handle_value;
                    for desc in descriptors {
                        if let Some(_desc_uuid) = desc.uuid {
                            #code_descs
                        }
                    }
                }
            }
        ));

        code_disc_done.extend(quote_spanned!(ch.span=>
            if self.#value_handle == 0 {
                return Err(#ble::gatt_client::DiscoverError::ServiceIncomplete);
            }
        ));

        if read {
            code_impl.extend(quote_spanned!(ch.span=>
                #fn_vis async fn #read_fn(&self) -> Result<#ty, #ble::gatt_client::ReadError> {
                    let mut buf = [0; #ty_as_val::MAX_SIZE];
                    let len = #ble::gatt_client::read(&self.conn, self.#value_handle, &mut buf).await?;
                    Ok(#ty_as_val::from_gatt(&buf[..len]))
                }
            ));
        }

        if write {
            code_impl.extend(quote_spanned!(ch.span=>
                #fn_vis async fn #write_fn(&self, val: &#ty) -> Result<(), #ble::gatt_client::WriteError> {
                    let buf = #ty_as_val::to_gatt(val);
                    #ble::gatt_client::write(&self.conn, self.#value_handle, buf).await
                }
                #fn_vis async fn #write_wor_fn(&self, val: &#ty) -> Result<(), #ble::gatt_client::WriteError> {
                    let buf = #ty_as_val::to_gatt(val);
                    #ble::gatt_client::write_without_response(&self.conn, self.#value_handle, buf).await
                }
                #fn_vis fn #write_try_wor_fn(&self, val: &#ty) -> Result<(), #ble::gatt_client::TryWriteError> {
                    let buf = #ty_as_val::to_gatt(val);
                    #ble::gatt_client::try_write_without_response(&self.conn, self.#value_handle, buf)
                }
            ));
        }

        if indicate || notify {
            fields.push(syn::Field {
                ident: Some(cccd_handle.clone()),
                ty: syn::Type::Verbatim(quote!(u16)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: syn::Visibility::Inherited,
            });
            code_disc_new.extend(quote_spanned!(ch.span=>
                #cccd_handle: 0,
            ));
            code_disc_done.extend(quote_spanned!(ch.span=>
                if self.#cccd_handle == 0 {
                    return Err(#ble::gatt_client::DiscoverError::ServiceIncomplete);
                }
            ));
        }

        if notify {
            let case_notification = format_ident!("{}Notification", name_pascal);
            code_event_enum.extend(quote_spanned!(ch.span=>
                #case_notification(#ty),
            ));
            code_on_hvx.extend(quote_spanned!(ch.span=>
                if handle == self.#value_handle && type_ == ::nrf_softdevice::ble::gatt_client::HvxType::Notification {
                    if data.len() < #ty_as_val::MIN_SIZE {
                        return None;
                    } else {
                        return Some(#event_enum_name::#case_notification(#ty_as_val::from_gatt(data)));
                    }
                }
            ));

            if !indicate {
                code_impl.extend(quote_spanned!(ch.span=>
                    #fn_vis async fn #cccd_write_fn(&self, notifications: bool) -> Result<(), #ble::gatt_client::WriteError> {
                        #ble::gatt_client::write(&self.conn, self.#cccd_handle, &[if notifications { 0x01 } else { 0x00 }, 0x00]).await
                    }
                ));
            }
        }

        if indicate {
            let case_indication = format_ident!("{}Indication", name_pascal);
            code_event_enum.extend(quote_spanned!(ch.span=>
                #case_indication(#ty),
            ));
            code_on_hvx.extend(quote_spanned!(ch.span=>
                if handle == self.#value_handle && type_ == ::nrf_softdevice::ble::gatt_client::HvxType::Indication {
                    if data.len() < #ty_as_val::MIN_SIZE {
                        return None;
                    } else {
                        return Some(#event_enum_name::#case_indication(#ty_as_val::from_gatt(data)));
                    }
                }
            ));

            if !notify {
                code_impl.extend(quote_spanned!(ch.span=>
                    #fn_vis async fn #cccd_write_fn(&self, indications: bool) -> Result<(), #ble::gatt_client::WriteError> {
                        #ble::gatt_client::write(&self.conn, self.#cccd_handle, &[if indications { 0x02 } else { 0x00 }, 0x00]).await
                    }
                ));
            }
        }

        if indicate && notify {
            code_impl.extend(quote_spanned!(ch.span=>
                #fn_vis async fn #cccd_write_fn(&self, indications: bool, notifications: bool) -> Result<(), #ble::gatt_client::WriteError> {
                    #ble::gatt_client::write(&self.conn, self.#cccd_handle, &[if indications { 0x02 } else { 0x00 } | if notifications { 0x01 } else { 0x00 }, 0x00]).await
                }
            ));
        }
    }

    let uuid = args.uuid;
    struct_fields.named = syn::punctuated::Punctuated::from_iter(fields);

    let vis = struc.vis.clone();
    let result = quote! {
        #struc

        #[allow(unused)]
        impl #struct_name {
            #code_impl
        }

        impl #ble::gatt_client::Client for #struct_name {
            type Event = #event_enum_name;

            fn on_hvx(&self, _conn: &::nrf_softdevice::ble::Connection, type_: ::nrf_softdevice::ble::gatt_client::HvxType, handle: u16, data: &[u8]) -> Option<Self::Event> {
                use #ble::gatt_client::Client;

                #code_on_hvx
                None
            }

            fn uuid() -> #ble::Uuid {
                #uuid
            }

            fn new_undiscovered(conn: #ble::Connection) -> Self {
                Self {
                    conn,
                    #code_disc_new
                }
            }

            fn discovered_characteristic(
                &mut self,
                characteristic: &#ble::gatt_client::Characteristic,
                descriptors: &[#ble::gatt_client::Descriptor],
            ) {
                #code_disc_char
            }

            fn discovery_complete(&mut self) -> Result<(), #ble::gatt_client::DiscoverError> {
                #code_disc_done
                Ok(())
            }
        }

        #vis enum #event_enum_name {
            #code_event_enum
        }
    };
    match ctxt.check() {
        Ok(()) => result.into(),
        Err(e) => e.into(),
    }
}
