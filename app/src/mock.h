// mock.h - synthesizes CONN_OPEN/DATA records straight into the model so the UI
// (flows table, hex inspector, throughput, animations) can be exercised without
// the driver. Toggled by AppState::mockData; also a handy UI-iteration harness.
#pragma once

#include "app_model.h"

void Mock_Pump(KndModel& model, double now);
