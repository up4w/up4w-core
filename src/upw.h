#include "../externs/miniposix/essentials.h"
#include "../src/net_types.h"

namespace upw
{

struct upw_status
{
    bool    want_exit;
    int32_t api_port;
};

bool start(os::CommandLine& cmd);
void stop();
void status(upw_status* out);

} // namespace upw
