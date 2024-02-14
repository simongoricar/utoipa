//! Implements [OpenApi Responses][responses].
//!
//! [responses]: https://spec.openapis.org/oas/latest.html#responses-object
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::openapi::{Ref, RefOr};
use crate::IntoResponses;

use super::{builder, header::Header, set_value, Content};

builder! {
    ResponsesBuilder;

    /// Implements [OpenAPI Responses Object][responses].
    ///
    /// Responses is a map holding api operation responses identified by their status code.
    ///
    /// [responses]: https://spec.openapis.org/oas/latest.html#responses-object
    #[non_exhaustive]
    #[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
    #[cfg_attr(feature = "debug", derive(Debug))]
    #[serde(rename_all = "camelCase")]
    pub struct Responses {
        /// Map containing status code as a key with represented response as a value.
        #[serde(flatten)]
        pub responses: BTreeMap<String, RefOr<Response>>,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MergeResult {
    Merged,
    NonMergeable,
}

fn merge_response_contents(existing_content: &mut Content, new_content: Content) -> MergeResult {
    // Attempt to merge `Content`s.
    match (&mut existing_content.schema, new_content.schema) {
        (RefOr::Ref(existing_schema_ref), RefOr::Ref(new_schema_ref)) => {
            if existing_schema_ref.ref_location != new_schema_ref.ref_location {
                // The responses don't point to the same object, we must give up on the merge.
                return MergeResult::NonMergeable;
            }
        }
        (RefOr::T(existing_schema), RefOr::T(mut new_schema)) => {
            if existing_schema != &mut new_schema {
                // The response schemas are not the same, which means we can't merge.
                return MergeResult::NonMergeable;
            }
        }
        _ => {
            // There's one schema by reference and one concrete schema, which means
            // we must give up on the merge.
            return MergeResult::NonMergeable;
        }
    };

    // Smartly merge examples by switching to `examples` from `example` if there are multiple.
    if let Some(existing_example) = &mut existing_content.example {
        if new_content.example.is_some() || !new_content.examples.is_empty() {
            // We'll need to collect and switch all examples to the `examples` field.
            // The keys will be derived from the hashed [`Example`][super::example::Example]s
            // using the default hasher.

            let existing_content_example_value = existing_example.to_owned();
            let existing_content_example_value_display = existing_content_example_value.to_string();
            let existing_content_example = super::example::Example {
                value: Some(existing_content_example_value),
                ..Default::default()
            };
            let existing_content_example_hash = {
                let mut default_hasher = DefaultHasher::new();
                existing_content_example_value_display.hash(&mut default_hasher);
                default_hasher.finish().to_string()
            };

            existing_content.examples.insert(
                existing_content_example_hash,
                RefOr::T(existing_content_example),
            );

            // PANIC SAFETY: We just called `is_some`.
            let new_content_example_value = new_content.example.unwrap();
            let new_content_example_value_display = new_content_example_value.to_string();
            let new_content_example = super::example::Example {
                value: Some(new_content_example_value),
                ..Default::default()
            };
            let new_content_example_hash = {
                let mut default_hasher = DefaultHasher::new();
                new_content_example_value_display.hash(&mut default_hasher);
                default_hasher.finish().to_string()
            };

            existing_content
                .examples
                .insert(new_content_example_hash, RefOr::T(new_content_example));

            existing_content.examples.extend(new_content.examples);
        }
    } else if !existing_content.examples.is_empty() {
        // Simply append the new `Content`'s `example` and `examples` to the existing `examples` field.
        // The keys will be derived from the hashed [`Example`][super::example::Example]s
        // using the default hasher.

        let new_content_example_value = new_content.example.unwrap();
        let new_content_example_value_display = new_content_example_value.to_string();
        let new_content_example = super::example::Example {
            value: Some(new_content_example_value),
            ..Default::default()
        };
        let new_content_example_hash = {
            let mut default_hasher = DefaultHasher::new();
            new_content_example_value_display.hash(&mut default_hasher);
            default_hasher.finish().to_string()
        };

        existing_content
            .examples
            .insert(new_content_example_hash, RefOr::T(new_content_example));

        existing_content.examples.extend(new_content.examples);
    }

    MergeResult::Merged
}

fn merge_responses(existing_response: &mut Response, new_response: Response) -> MergeResult {
    // Perform partial response merge.
    let merged_descriptions = format!(
        "{}\n\n*OR*\n\n{}",
        existing_response.description, new_response.description
    );
    existing_response.description = merged_descriptions;

    existing_response.headers.extend(new_response.headers);

    for (new_content_type, new_content) in new_response.content {
        if let Some(existing_content) = existing_response.content.get_mut(&new_content_type) {
            // Attempt to merge `Content`s.
            let merge_result = merge_response_contents(existing_content, new_content);

            // If the merge can't be performed, we must fall back to overwriting the entire response.
            if merge_result == MergeResult::NonMergeable {
                return MergeResult::NonMergeable;
            }
        } else {
            existing_response
                .content
                .insert(new_content_type, new_content);
        }
    }

    if let Some(new_extensions_map) = new_response.extensions {
        if let Some(existing_extensions_map) = &mut existing_response.extensions {
            existing_extensions_map.extend(new_extensions_map);
        } else {
            existing_response.extensions = Some(new_extensions_map);
        }
    }

    MergeResult::Merged
}

impl Responses {
    pub fn new() -> Self {
        Default::default()
    }
}

impl ResponsesBuilder {
    /// Add a [`Response`].
    pub fn response<S: Into<String>, R: Into<RefOr<Response>>>(
        mut self,
        code: S,
        response: R,
    ) -> Self {
        let code = code.into();
        let response = response.into();

        if let Some(existing_response) = self.responses.get_mut(&code) {
            // Status code collision - attempt to merge responses.

            let RefOr::T(existing_response_inner) = existing_response else {
                // As the existing response is a reference,
                // we can't modify it - give up (overwrites existing).
                self.responses.insert(code, response);
                return self;
            };

            let RefOr::T(new_response_inner) = response.clone() else {
                // As the new response is a reference,
                // we can't modify it - give up (overwrites existing).
                self.responses.insert(code, response);
                return self;
            };

            let merge_result = merge_responses(existing_response_inner, new_response_inner.clone());

            if merge_result == MergeResult::NonMergeable {
                // Failed to merge properly, fall back to overwriting.
                self.responses.insert(code, response);
            }
        } else {
            // No status code collision, proceed as usual.
            self.responses.insert(code, response);
        }

        self
    }

    /// Add responses from an iterator over a pair of `(status_code, response): (String, Response)`.
    pub fn responses_from_iter<
        I: IntoIterator<Item = (C, R)>,
        C: Into<String>,
        R: Into<RefOr<Response>>,
    >(
        mut self,
        iter: I,
    ) -> Self {
        for (code, response) in iter {
            self = self.response(code, response);
        }

        self
    }

    /// Add responses from a type that implements [`IntoResponses`].
    pub fn responses_from_into_responses<I: IntoResponses>(mut self) -> Self {
        for (code, response) in I::responses() {
            self = self.response(code, response);
        }

        self
    }
}

impl From<Responses> for BTreeMap<String, RefOr<Response>> {
    fn from(responses: Responses) -> Self {
        responses.responses
    }
}

impl<C, R> FromIterator<(C, R)> for Responses
where
    C: Into<String>,
    R: Into<RefOr<Response>>,
{
    fn from_iter<T: IntoIterator<Item = (C, R)>>(iter: T) -> Self {
        Self {
            responses: BTreeMap::from_iter(
                iter.into_iter()
                    .map(|(code, response)| (code.into(), response.into())),
            ),
        }
    }
}

builder! {
    ResponseBuilder;

    /// Implements [OpenAPI Response Object][response].
    ///
    /// Response is api operation response.
    ///
    /// [response]: https://spec.openapis.org/oas/latest.html#response-object
    #[non_exhaustive]
    #[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
    #[cfg_attr(feature = "debug", derive(Debug))]
    #[serde(rename_all = "camelCase")]
    pub struct Response {
        /// Description of the response. Response support markdown syntax.
        pub description: String,

        /// Map of headers identified by their name. `Content-Type` header will be ignored.
        #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
        pub headers: BTreeMap<String, Header>,

        /// Map of response [`Content`] objects identified by response body content type e.g `application/json`.
        ///
        /// [`Content`]s are stored within [`IndexMap`] to retain their insertion order. Swagger UI
        /// will create and show default example according to the first entry in `content` map.
        #[serde(skip_serializing_if = "IndexMap::is_empty", default)]
        pub content: IndexMap<String, Content>,

        /// Optional extensions "x-something".
        #[serde(skip_serializing_if = "Option::is_none", flatten)]
        pub extensions: Option<HashMap<String, serde_json::Value>>,
    }
}

impl Response {
    /// Construct a new [`Response`].
    ///
    /// Function takes description as argument.
    pub fn new<S: Into<String>>(description: S) -> Self {
        Self {
            description: description.into(),
            ..Default::default()
        }
    }
}

impl ResponseBuilder {
    /// Add description. Description supports markdown syntax.
    pub fn description<I: Into<String>>(mut self, description: I) -> Self {
        set_value!(self description description.into())
    }

    /// Add [`Content`] of the [`Response`] with content type e.g `application/json`.
    pub fn content<S: Into<String>>(mut self, content_type: S, content: Content) -> Self {
        self.content.insert(content_type.into(), content);

        self
    }

    /// Add response [`Header`].
    pub fn header<S: Into<String>>(mut self, name: S, header: Header) -> Self {
        self.headers.insert(name.into(), header);

        self
    }

    /// Add openapi extensions (x-something) to the [`Header`].
    pub fn extensions(mut self, extensions: Option<HashMap<String, serde_json::Value>>) -> Self {
        set_value!(self extensions extensions)
    }
}

impl From<ResponseBuilder> for RefOr<Response> {
    fn from(builder: ResponseBuilder) -> Self {
        Self::T(builder.build())
    }
}

impl From<Ref> for RefOr<Response> {
    fn from(r: Ref) -> Self {
        Self::Ref(r)
    }
}

/// Trait with convenience functions for documenting response bodies.
///
/// With a single method call we can add [`Content`] to our [`ResponseBuilder`] and [`Response`]
/// that references a [schema][schema] using content-type `"application/json"`.
///
/// _**Add json response from schema ref.**_
/// ```rust
/// use utoipa::openapi::response::{ResponseBuilder, ResponseExt};
///
/// let request = ResponseBuilder::new()
///     .description("A sample response")
///     .json_schema_ref("MyResponsePayload").build();
/// ```
///
/// If serialized to JSON, the above will result in a response schema like this.
/// ```json
/// {
///   "description": "A sample response",
///   "content": {
///     "application/json": {
///       "schema": {
///         "$ref": "#/components/schemas/MyResponsePayload"
///       }
///     }
///   }
/// }
/// ```
///
/// [response]: crate::ToResponse
/// [schema]: crate::ToSchema
///
#[cfg(feature = "openapi_extensions")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "openapi_extensions")))]
pub trait ResponseExt {
    /// Add [`Content`] to [`Response`] referring to a _`schema`_
    /// with Content-Type `application/json`.
    fn json_schema_ref(self, ref_name: &str) -> Self;
}

#[cfg(feature = "openapi_extensions")]
impl ResponseExt for Response {
    fn json_schema_ref(mut self, ref_name: &str) -> Response {
        self.content.insert(
            "application/json".to_string(),
            Content::new(crate::openapi::Ref::from_schema_name(ref_name)),
        );
        self
    }
}

#[cfg(feature = "openapi_extensions")]
impl ResponseExt for ResponseBuilder {
    fn json_schema_ref(self, ref_name: &str) -> ResponseBuilder {
        self.content(
            "application/json",
            Content::new(crate::openapi::Ref::from_schema_name(ref_name)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Content, ResponseBuilder, Responses};
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn responses_new() {
        let responses = Responses::new();

        assert!(responses.responses.is_empty());
    }

    #[test]
    fn response_builder() -> Result<(), serde_json::Error> {
        let request_body = ResponseBuilder::new()
            .description("A sample response")
            .content(
                "application/json",
                Content::new(crate::openapi::Ref::from_schema_name("MySchemaPayload")),
            )
            .build();
        let serialized = serde_json::to_string_pretty(&request_body)?;
        println!("serialized json:\n {serialized}");
        assert_json_eq!(
            request_body,
            json!({
              "description": "A sample response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/MySchemaPayload"
                  }
                }
              }
            })
        );
        Ok(())
    }
}

#[cfg(all(test, feature = "openapi_extensions"))]
mod openapi_extensions_tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use crate::openapi::ResponseBuilder;

    use super::ResponseExt;

    #[test]
    fn response_ext() {
        let request_body = ResponseBuilder::new()
            .description("A sample response")
            .build()
            .json_schema_ref("MySchemaPayload");

        assert_json_eq!(
            request_body,
            json!({
              "description": "A sample response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/MySchemaPayload"
                  }
                }
              }
            })
        );
    }

    #[test]
    fn response_builder_ext() {
        let request_body = ResponseBuilder::new()
            .description("A sample response")
            .json_schema_ref("MySchemaPayload")
            .build();
        assert_json_eq!(
            request_body,
            json!({
              "description": "A sample response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/MySchemaPayload"
                  }
                }
              }
            })
        );
    }
}
