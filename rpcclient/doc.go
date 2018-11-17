// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package rpcclient implements Dash JSON-RPC client.

Overview

This client provides a robust and easy to use client for interfacing with a
Dash RPC server.

HTTP POST

In HTTP POST-based JSON-RPC, every request creates a new HTTP connection,
issues the call, waits for the response, and closes the connection.  This adds
quite a bit of overhead to every call and lacks flexibility for features such as
notifications.

Synchronous vs Asynchronous API

The client provides both a synchronous (blocking) and asynchronous API.

The synchronous (blocking) API is typically sufficient for most use cases.  It
works by issuing the RPC and blocking until the response is received.  This
allows  straightforward code where you have the response as soon as the function
returns.

The asynchronous API works on the concept of futures.  When you invoke the async
version of a command, it will quickly return an instance of a type that promises
to provide the result of the RPC at some future time.  In the background, the
RPC call is issued and the result is stored in the returned instance.  Invoking
the Receive method on the returned instance will either return the result
immediately if it has already arrived, or block until it has.  This is useful
since it provides the caller with greater control over concurrency.

Errors

There are 3 categories of errors that will be returned throughout this package:

  - Errors related to the client connection such as authentication, endpoint,
    disconnect, and shutdown
  - Errors that occur before communicating with the remote RPC server such as
    command creation and marshaling errors or issues talking to the remote
    server
  - Errors returned from the remote RPC server like unimplemented commands,
    nonexistent requested blocks and transactions, malformed data, and incorrect
    networks

The first category of errors are typically one of ErrInvalidAuth,
ErrInvalidEndpoint, ErrClientDisconnect, or ErrClientShutdown.

NOTE: The ErrClientDisconnect will not be returned unless the
DisableAutoReconnect flag is set since the client automatically handles
reconnect by default as previously described.

The second category of errors typically indicates a programmer error and as such
the type can vary, but usually will be best handled by simply showing/logging
it.

The third category of errors, that is errors returned by the server, can be
detected by type asserting the error in a *btcjson.RPCError.  For example, to
detect if a command is unimplemented by the remote RPC server:

  amount, err := client.GetBalance("")
  if err != nil {
  	if jerr, ok := err.(*btcjson.RPCError); ok {
  		switch jerr.Code {
  		case btcjson.ErrRPCUnimplemented:
  			// Handle not implemented error

  		// Handle other specific errors you care about
		}
  	}

  	// Log or otherwise handle the error knowing it was not one returned
  	// from the remote RPC server.
  }

*/
package rpcclient
