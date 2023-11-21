use actix_web::dev::ServiceResponse;
use actix_web::http::{header, };
use actix_web::middleware::{ErrorHandlerResponse, ErrorHandlers};

pub fn add_error_header<B>(mut res: ServiceResponse<B>) -> actix_web::Result<ErrorHandlerResponse<B>> {
    res.response_mut().headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("Error"),
    );

    // body is unchanged, map to "left" slot
    Ok(ErrorHandlerResponse::Response(res.map_into_left_body()))
}

pub fn handle_404<B>(mut res: ServiceResponse<B>) -> actix_web::Result<ErrorHandlerResponse<B>> {
    res.response_mut().headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("404 not found"),
    );

    // body is unchanged, map to "left" slot
    Ok(ErrorHandlerResponse::Response(res.map_into_left_body()))
}
